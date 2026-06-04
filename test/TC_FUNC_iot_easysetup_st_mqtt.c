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
#include <iot_internal.h>
#include <iot_main.h>
#include <iot_security_util.h>
#include <iot_util.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cmocka_custom.h"

#define REG_TEST_LOOKUP_ID "c37e0475-b727-49ca-bdfe-33bda78c28a7";
#define REG_TEST_LOCATION_ID "9400c47a-5d29-452c-bb36-0a44c08eba19";
#define REG_TEST_ROOM_ID "7be9ec0b-8819-44f9-ac26-2f4e46f48731"
#define REG_TEST_DIP_ID "2154ccfc-84d1-432f-8c0d-5651b5a0da8e"
#define REG_TEST_HASHED_SN "VNZCGRB2VIt+4QckH7OWZPp8UxulH/nZDCDgXpPHr1M"  // stdktest00000001
#define REG_TEST_COMBO_SN "mEjwVaheS8yMJ2QeHLbqlgWsuVmsJmgEGCuGeCQ1BXE="  // stdktest00000001
#define REG_TEST_LABEL "testLabel"
#define REG_TEST_MNID "fTST"
#define REG_TEST_VID "TEST_VID"
#define REG_TEST_DEVICE_TYPE "Light"
#define REG_TEST_DIP_ID "2154ccfc-84d1-432f-8c0d-5651b5a0da8e"
#define REG_TEST_FW_VERSION "testFirmware"
#define REG_TEST_MODEL_NUMBER "testModel"
#define REG_TEST_MARKETING_NAME "testMarketingName"
#define REG_TEST_MANUFACTURER_NAME "testManufacturerName"
#define REG_TEST_MANUFACTURER_CODE "testManufacturerCode"

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
void TC_STATIC_iot_es_mqtt_registration_success(void **state)
{
    // TODO: test for cbor
}
#else
extern void *_iot_es_mqtt_registration_json(struct iot_context *ctx, char *dip_id, size_t *msglen);
static void assert_es_mqtt_registration_json(struct iot_context *context, char *payload, size_t msglen,
                                             bool serial_type);
static struct iot_context *generate_es_mqtt_registration_context(bool use_opt, bool serial_type);
struct registration_test_condition {
    bool use_opt;
};

void TC_STATIC_iot_es_mqtt_registration_SUCCESS(void **state)
{
    char *output_str;
    size_t msglen;
    struct iot_context *context;
    char *dip_id = REG_TEST_DIP_ID;
    struct registration_test_condition condition[2] = {
        {false},
        {true},
    };

    /*
        serial type for the registration has hashed sn and combo sn
        if serial_type is true, serial type is combo sn
        if serial_type is false, serial type is hashed sn
    */
    bool serial_type;  // serial_type(Hashed sn, Combo sn)

    for (int sn_type_count = 0; sn_type_count < 2; sn_type_count++) {
        for (int i = 0; i < 2; i++) {
            // Given
            context = generate_es_mqtt_registration_context(condition[i].use_opt, serial_type);
            // When
            output_str = _iot_es_mqtt_registration_json(context, dip_id, &msglen);
            // Then
            assert_es_mqtt_registration_json(context, output_str, msglen, serial_type);
            // Teardown
            free(output_str);
            free(context->devconf.dip);
            free(context);
        }
    }
}

void TC_STATIC_iot_es_mqtt_registration_json_NULL_context(void **state)
{
    // Given: NULL context
    struct iot_context *context = NULL;
    char *dip_id = REG_TEST_DIP_ID;
    size_t msglen = 0;

    // When
    char *result = _iot_es_mqtt_registration_json(context, dip_id, &msglen);

    // Then
    assert_null(result);
    assert_int_equal(msglen, 0);
}

void TC_STATIC_iot_es_mqtt_registration_json_no_serial(void **state)
{
    // Given: Context with no serial numbers
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));
    context->lookup_id = REG_TEST_LOOKUP_ID;
    context->devconf.mnid = REG_TEST_MNID;
    context->devconf.vid = REG_TEST_VID;
    context->devconf.device_type = REG_TEST_DEVICE_TYPE;

    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    char *dip_id = REG_TEST_DIP_ID;
    size_t msglen = 0;

    // When
    char *result = _iot_es_mqtt_registration_json(context, dip_id, &msglen);

    // Then
    assert_null(result);
    assert_int_equal(msglen, 0);

    // Teardown
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_json_no_lookup_id(void **state)
{
    // Given: Context with no lookup_id
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    // Add serial numbers
    context->devconf.hashed_sn = REG_TEST_HASHED_SN;

    context->devconf.mnid = REG_TEST_MNID;
    context->devconf.vid = REG_TEST_VID;
    context->devconf.device_type = REG_TEST_DEVICE_TYPE;

    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    char *dip_id = REG_TEST_DIP_ID;
    size_t msglen = 0;

    // When
    char *result = _iot_es_mqtt_registration_json(context, dip_id, &msglen);

    // Then
    assert_non_null(result);
    assert_int_not_equal(msglen, 0);

    // Teardown
    free(result);
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_json_no_dip_data(void **state)
{
    // Given: Context with no DIP data
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->lookup_id = REG_TEST_LOOKUP_ID;

    // Add serial numbers
    context->devconf.hashed_sn = REG_TEST_HASHED_SN;

    context->devconf.mnid = REG_TEST_MNID;
    context->devconf.vid = REG_TEST_VID;
    context->devconf.device_type = REG_TEST_DEVICE_TYPE;

    char *dip_id = NULL;  // No DIP ID
    size_t msglen = 0;

    // When
    char *result = _iot_es_mqtt_registration_json(context, dip_id, &msglen);

    // Then
    assert_non_null(result);
    assert_int_not_equal(msglen, 0);

    // Teardown
    free(result);
    free(context);
}

struct iot_context *generate_es_mqtt_registration_context(bool use_opt, bool serial_type)
{
    struct iot_context *context;
    struct iot_devconf_prov_data *devconf;
    struct iot_device_info *dev_info;

    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->lookup_id = REG_TEST_LOOKUP_ID;

    devconf = &context->devconf;
    devconf->hashed_sn = REG_TEST_HASHED_SN;
    if (serial_type) {
        devconf->combo_sn = iot_os_malloc(sizeof(REG_TEST_COMBO_SN) + 1);
        assert_non_null(devconf->combo_sn);

        memset(devconf->combo_sn, '\0', sizeof(REG_TEST_COMBO_SN) + 1);
        memcpy(devconf->combo_sn, REG_TEST_COMBO_SN, sizeof(REG_TEST_COMBO_SN) + 1);
    }
    devconf->mnid = REG_TEST_MNID;
    devconf->vid = REG_TEST_VID;
    devconf->device_type = REG_TEST_DEVICE_TYPE;
    devconf->dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &devconf->dip->dip_id);
    devconf->dip->dip_major_version = 0;
    devconf->dip->dip_minor_version = 1;

    if (use_opt) {
        dev_info = &context->device_info;
        dev_info->opt_info = true;
        dev_info->firmware_version = REG_TEST_FW_VERSION;
        dev_info->model_number = REG_TEST_MODEL_NUMBER;
        dev_info->marketing_name = REG_TEST_MARKETING_NAME;
        dev_info->manufacturer_name = REG_TEST_MANUFACTURER_NAME;
        dev_info->manufacturer_code = REG_TEST_MANUFACTURER_CODE;
    }

    return context;
}

void assert_es_mqtt_registration_json(struct iot_context *context, char *payload, size_t msglen, bool serial_type)
{
    JSON_H *root;

    assert_non_null(context);
    assert_non_null(payload);
    assert_int_equal(strlen(payload), msglen);

    root = JSON_PARSE(payload);
    assert_string_equal(context->lookup_id, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "lookupId")));
    if (context->prov_data.cloud.location) {
        assert_string_equal(context->prov_data.cloud.location,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "locationId")));
    }
    if (context->prov_data.cloud.room) {
        assert_string_equal(context->prov_data.cloud.room, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "roomId")));
    } else {
        if (serial_type)
            assert_string_equal(REG_TEST_COMBO_SN, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "serialHash")));
        else
            assert_string_equal(REG_TEST_HASHED_SN, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "serialHash")));

        assert_non_null(JSON_GET_OBJECT_ITEM(root, "provisioningTs"));
    }

    if (context->prov_data.cloud.label) {
        assert_string_equal(context->prov_data.cloud.label, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "label")));
    }

    if (context->device_info.opt_info) {
        assert_string_equal(context->device_info.firmware_version,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "firmwareVersion")));
        assert_string_equal(context->device_info.model_number,
                            JSON_GET_STRING_VALUE((JSON_GET_OBJECT_ITEM(root, "modelNumber"))));
        assert_string_equal(context->device_info.marketing_name,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "marketingName")));
        assert_string_equal(context->device_info.manufacturer_name,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "manufacturerName")));
        assert_string_equal(context->device_info.manufacturer_code,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "manufacturerCode")));
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "firmwareVersion"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "modelNumber"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "marketingName"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "manufacturerName"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "manufacturerCode"));
    }
    if (iot_os_get_os_name()) {
        assert_string_equal(iot_os_get_os_name(), JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "osType")));
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "osType"));
    }

    if (iot_os_get_os_version_string()) {
        assert_string_equal(iot_os_get_os_version_string(),
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "osVersion")));
        ;
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "osVersion"));
    }
    assert_string_equal(STDK_VERSION_STRING, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "stdkVersion")));

    if (context->devconf.dip) {
        iot_error_t err;
        JSON_H *dip_item;
        char *str_id;
        size_t str_id_len = 40;

        str_id = (char *)malloc(str_id_len);
        assert_non_null(str_id);
        memset(str_id, 0, str_id_len);
        err = iot_util_convert_uuid_str(&context->devconf.dip->dip_id, str_id, str_id_len);
        assert_int_equal(err, IOT_ERROR_NONE);
        dip_item = JSON_GET_OBJECT_ITEM(root, "deviceIntegrationProfileKey");
        assert_string_equal(str_id, JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(dip_item, "id")));
        free(str_id);

        assert_int_equal(context->devconf.dip->dip_major_version,
                         JSON_GET_OBJECT_ITEM(dip_item, "majorVersion")->valueint);
        assert_int_equal(context->devconf.dip->dip_minor_version,
                         JSON_GET_OBJECT_ITEM(dip_item, "minorVersion")->valueint);
    }
}

extern int _iot_parse_sequence_num(char *payload);

void TC_STATIC_iot_parse_sequence_num_SUCCESS(void **state)
{
    const char *mqtt_payload[3] = {
        "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switch\",\"attribute\":\"switch\",\"value\":"
        "\"on\",\"providerData\":{\"sequenceNumber\":1,\"timestamp\":\"1598246160400\"}}]}",
        "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switchLevel\",\"attribute\":\"level\",\"value\":"
        "50,\"unit\":\"%\",\"providerData\":{\"sequenceNumber\":2,\"timestamp\":\"1598246160419\"}}]}",
        "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"colorTemperature\",\"attribute\":"
        "\"colorTemperature\",\"value\":2000,\"providerData\":{\"sequenceNumber\":3,\"timestamp\":\"1598246160437\"}}]"
        "}"};
    int expected_sequence_num[3] = {1, 2, 3};

    for (int i = 0; i < 3; i++) {
        int seq = _iot_parse_sequence_num((char *)mqtt_payload[i]);
        assert_int_equal(seq, expected_sequence_num[i]);
    }
}

void TC_STATIC_iot_parse_sequence_num_FAILURE(void **state)
{
    const char *mqtt_payload[4] = {
        NULL, "{}",
        "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switch\",\"attribute\":\"switch\",\"value\":"
        "\"on\"}]}",
        "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"colorTemperature\",\"attribute\":"
        "\"colorTemperature\",\"value\":2000,\"providerData\":{\"timestamp\":\"1598246160437\"}}]}"};

    for (int i = 0; i < 4; i++) {
        int seq = _iot_parse_sequence_num((char *)mqtt_payload[i]);
        assert_int_equal(seq, 0);
    }
}

void TC_STATIC_iot_parse_sequence_num_NULL_payload(void **state)
{
    // Given: NULL payload
    char *payload = NULL;

    // When
    int result = _iot_parse_sequence_num(payload);

    // Then
    assert_int_equal(result, 0);
}

void TC_STATIC_iot_parse_sequence_num_empty_string(void **state)
{
    // Given: Empty string payload
    char *payload = "";

    // When
    int result = _iot_parse_sequence_num(payload);

    // Then
    assert_int_equal(result, 0);
}

void TC_STATIC_iot_parse_sequence_num_invalid_json(void **state)
{
    // Given: Invalid JSON payload
    char *payload = "{ invalid json }";

    // When
    int result = _iot_parse_sequence_num(payload);

    // Then
    assert_int_equal(result, 0);
}

void TC_STATIC_iot_parse_sequence_num_no_device_events(void **state)
{
    // Given: JSON without deviceEvents
    char *payload = "{\"someOtherKey\":\"value\"}";

    // When
    int result = _iot_parse_sequence_num(payload);

    // Then
    assert_int_equal(result, 0);
}

void TC_STATIC_iot_parse_sequence_num_empty_device_events(void **state)
{
    // Given: JSON with empty deviceEvents array
    char *payload = "{\"deviceEvents\":[]}";

    // When
    int result = _iot_parse_sequence_num(payload);

    // Then
    assert_int_equal(result, 0);
}

#define DIP_MAJOR_VERSION "0"
#define DIP_MINOR_VERSION "1"
#define DIP_KEY "123e4567-e89b-12d3-a456-426614174000"
#define REG_DEVICE_ID "123e4567-e89b-12d3-a456-426614174000"
#define REG_LOCATION_ID "123e4567-e89b-12d3-a456-426614174000"
extern void _iot_mqtt_registration_client_callback(st_mqtt_event event, void *event_data, void *user_data);

void TC_STATIC_iot_mqtt_registration_client_callback_SUCCESS(void **state)
{
    st_mqtt_msg msg;
    struct iot_uuid uuid;
    struct iot_context *context;
    char *reg_payload =
        "{\"deviceId\":\"" REG_DEVICE_ID
        "\",\n"
        "\"name\":\"Light\",\n"
        "\"label\":\"Light\",\n"
        "\"locationId\":\"" REG_LOCATION_ID
        "\",\n"
        "\"roomId\":\"123e4567-e89b-12d3-a456-426614174000\",\n"
        "\"type\":\"MQTT\",\n"
        "\"deviceIntegrationProfileKey\":{\"id\":\"" DIP_KEY "\",\"majorVersion\":" DIP_MAJOR_VERSION
        ",\"minorVersion\":" DIP_MINOR_VERSION
        "},\n"
        "\"routingKey\":\"us\",\n"
        "\"metadata\":{\"serialNumber\":\"SERIALNUMBER\",\"mnId\":\"MNID\",\"vid\":\"VIDTEST\",\"deviceTypeId\":"
        "\"Light\",\n"
        "             "
        "\"lookupId\":\"bb000ddd-92a0-42a3-86f0-b531f278af06\",\"registrationPayloadType\":\"json\",\"stack\":\"K8\",\n"
        "             \"serialHash\":\"rpSpVp9nOkPowHrwBzA6UqyC48cJdYyBpyfZFqbZeh0\",\"provisioningTs\":1598256474,\n"
        "             \"manufacturerName\":\"Opensource\",\"manufacturerCode\":\"101\",\"marketingName\":\"Light "
        "Device\",\n"
        "             "
        "\"modelNumber\":\"TEST\",\"firmwareVersion\":\"1.3.6\",\"osType\":\"FreeRTOS\",\"osVersion\":\"V8.2.0\","
        "\"stdkVersion\":\"1.3.6\"}}";

    // Given
    context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;
    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, (void *)context);

    // Then
    assert_int_equal(context->iot_reg_data.dip->dip_major_version, atoi(DIP_MAJOR_VERSION));
    assert_int_equal(context->iot_reg_data.dip->dip_minor_version, atoi(DIP_MINOR_VERSION));
    iot_util_convert_str_uuid(DIP_KEY, &uuid);
    assert_memory_equal(&context->iot_reg_data.dip->dip_id, &uuid, sizeof(struct iot_uuid));
    iot_util_convert_str_uuid(REG_LOCATION_ID, &uuid);
    assert_memory_equal(context->iot_reg_data.locationId, &uuid, sizeof(struct iot_uuid));
    assert_string_equal(REG_DEVICE_ID, context->iot_reg_data.deviceId);

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    iot_os_free(context->iot_reg_data.dip);
    iot_os_free(context->iot_reg_data.locationId);
    free(context);
}

void TC_STATIC_iot_mqtt_registration_client_callback_NULL_context(void **state)
{
    // Given: NULL context
    st_mqtt_msg msg = {0};
    char *reg_payload = "{\"deviceId\":\"" REG_DEVICE_ID "\"}";

    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, NULL);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with NULL context
    assert_true(true);
}

void TC_STATIC_iot_mqtt_registration_client_callback_NULL_payload(void **state)
{
    // Given: Context with NULL payload
    st_mqtt_msg msg;
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    msg.payload = NULL;
    msg.payloadlen = 0;
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with NULL payload

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

void TC_STATIC_iot_mqtt_registration_client_callback_invalid_event(void **state)
{
    // Given: Invalid event type
    st_mqtt_msg msg;
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    char *reg_payload = "{\"deviceId\":\"" REG_DEVICE_ID "\"}";
    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_PUBLISH_FAILED, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with invalid event

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

void TC_STATIC_iot_mqtt_registration_client_callback_invalid_json(void **state)
{
    // Given: Invalid JSON payload
    st_mqtt_msg msg;
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    char *reg_payload = "{ invalid json }";
    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with invalid JSON

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

void TC_STATIC_iot_mqtt_registration_client_callback_expired_jwt(void **state)
{
    // Given: Expired JWT payload
    st_mqtt_msg msg;
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    char *reg_payload = "{\"event\":\"expired.jwt\"}";
    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with expired JWT and no currentTime

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

void TC_STATIC_iot_mqtt_registration_client_callback_error_event(void **state)
{
    // Given: Error event payload
    st_mqtt_msg msg;
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    char *reg_payload = "{\"event\":\"error\"}";
    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with error event

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

#endif /* STDK_IOT_CORE_SERIALIZE_CBOR */

extern gg_connection_request_status _check_connection_response(struct iot_context *ctx, char *response_payload,
                                                               size_t response_payload_len);

void TC_STATIC_check_connection_response_NULL_payload(void **state)
{
    // Given: NULL payload
    char *response_payload = NULL;
    size_t response_payload_len = 0;
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_FAIL);
}

void TC_STATIC_check_connection_response_empty_payload(void **state)
{
    // Given: Empty payload
    char *response_payload = "";
    size_t response_payload_len = 0;
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_FAIL);
}

void TC_STATIC_check_connection_response_invalid_json(void **state)
{
    // Given: Invalid JSON payload
    char *response_payload = "{ invalid json }";
    size_t response_payload_len = strlen(response_payload);
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_FAIL);
}

void TC_STATIC_check_connection_response_no_event(void **state)
{
    // Given: JSON without event field
    char *response_payload = "{\"someOtherKey\":\"value\"}";
    size_t response_payload_len = strlen(response_payload);
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_WAITING);
}

void TC_STATIC_check_connection_response_expired_jwt_no_current_time(void **state)
{
    // Given: Expired JWT without currentTime
    char *response_payload = "{\"event\":\"expired.jwt\"}";
    size_t response_payload_len = strlen(response_payload);
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_FAIL);
}

void TC_STATIC_check_connection_response_unknown_event(void **state)
{
    // Given: Unknown event type
    char *response_payload = "{\"event\":\"unknown.event\"}";
    size_t response_payload_len = strlen(response_payload);
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_WAITING);
}

void TC_STATIC_check_connection_response_connection_sucess(void **state)
{
    // Given: Unknown event type
    char *response_connect_success_payload = "{\"event\":\"connect.success\"}";
    char *response_connect_success_ACC_payload = "{\"event\":\"connect.success\", \"env\":\"ACC\"}";
    char *response_connect_success_STG_payload = "{\"event\":\"connect.success\", \"env\":\"STG\"}";
    char *response_connect_success_DEV_payload = "{\"event\":\"connect.success\", \"env\":\"DEV\"}";
    struct iot_context ctx = {
        0,
    };

    // When
    gg_connection_request_status result =
        _check_connection_response(&ctx, response_connect_success_payload, strlen(response_connect_success_payload));
    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_SUCCESS);
    assert_int_equal(ctx.server_env, SERVER_ENV_PRD);

    // When
    memset(&ctx, 0, sizeof(struct iot_context));
    result = _check_connection_response(&ctx, response_connect_success_ACC_payload,
                                        strlen(response_connect_success_ACC_payload));
    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_SUCCESS);
    assert_int_equal(ctx.server_env, SERVER_ENV_ACC);

    // When
    memset(&ctx, 0, sizeof(struct iot_context));
    result = _check_connection_response(&ctx, response_connect_success_STG_payload,
                                        strlen(response_connect_success_STG_payload));
    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_SUCCESS);
    assert_int_equal(ctx.server_env, SERVER_ENV_STG);

    // When
    memset(&ctx, 0, sizeof(struct iot_context));
    result = _check_connection_response(&ctx, response_connect_success_DEV_payload,
                                        strlen(response_connect_success_DEV_payload));
    // Then
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_SUCCESS);
    assert_int_equal(ctx.server_env, SERVER_ENV_DEV);
}

extern iot_error_t _iot_es_mqtt_connect(struct iot_context *ctx, st_mqtt_client target_cli, char *username,
                                        char *sign_data);

void TC_STATIC_iot_es_mqtt_connect_NULL_context(void **state)
{
    // Given: NULL context
    st_mqtt_client target_cli = NULL;
    char *username = "test_username";
    char *sign_data = "test_sign_data";

    // When
    iot_error_t result = _iot_es_mqtt_connect(NULL, target_cli, username, sign_data);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_mqtt_connect_NULL_username(void **state)
{
    // Given: NULL username
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    st_mqtt_client target_cli = NULL;
    char *sign_data = "test_sign_data";

    // When
    iot_error_t result = _iot_es_mqtt_connect(context, target_cli, NULL, sign_data);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

void TC_STATIC_iot_es_mqtt_connect_NULL_sign_data(void **state)
{
    // Given: NULL sign_data
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    st_mqtt_client target_cli = NULL;
    char *username = "test_username";

    // When
    iot_error_t result = _iot_es_mqtt_connect(context, target_cli, username, NULL);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

extern iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type);

void TC_STATIC_iot_es_connect_NULL_context(void **state)
{
    // Given: NULL context
    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_connect(NULL, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_connect_invalid_conn_type(void **state)
{
    // Given: Invalid connection type
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    int conn_type = -1;  // Invalid connection type

    // When
    iot_error_t result = iot_es_connect(context, conn_type);

    // Then
    assert_int_not_equal(result, IOT_ERROR_NONE);

    // Teardown
    free(context);
}

void TC_STATIC_iot_es_connect_rate_limit(void **state)
{
    // Given: Context with rate limit set
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->rate_limit = true;  // Set rate limit
    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_connect(context, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_MQTT_CONNECT_FAIL);

    // Teardown
    free(context);
}

extern iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type);

void TC_STATIC_iot_es_disconnect_NULL_context(void **state)
{
    // Given: NULL context
    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_disconnect(NULL, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_disconnect_invalid_conn_type(void **state)
{
    // Given: Invalid connection type
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    int conn_type = -1;  // Invalid connection type

    // When
    iot_error_t result = iot_es_disconnect(context, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

void TC_STATIC_iot_es_disconnect_no_mqtt_context(void **state)
{
    // Given: Context with no MQTT context
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    // Make sure both MQTT contexts are NULL
    context->evt_mqttcli = NULL;
    context->reg_mqttcli = NULL;

    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_disconnect(context, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

extern iot_error_t iot_update_dip(struct iot_context *ctx, st_mqtt_client mqtt_cli);

void TC_STATIC_iot_update_dip_NULL_context(void **state)
{
    // Given: NULL context
    st_mqtt_client mqtt_cli = NULL;

    // When
    iot_error_t result = iot_update_dip(NULL, mqtt_cli);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_update_dip_NULL_mqtt_client(void **state)
{
    // Given: NULL MQTT client
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    // When
    iot_error_t result = iot_update_dip(context, NULL);

    // Then
    assert_int_not_equal(result, IOT_ERROR_NONE);

    // Teardown
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_update_dip_no_dip_data(void **state)
{
    // Given: Context with no DIP data
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    st_mqtt_client mqtt_cli = NULL;

    // When
    iot_error_t result = iot_update_dip(context, mqtt_cli);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context);
}

extern iot_error_t _iot_es_mqtt_registration(struct iot_context *ctx, st_mqtt_client mqtt_ctx);

void TC_STATIC_iot_es_mqtt_registration_NULL_context(void **state)
{
    // Given: NULL context
    st_mqtt_client mqtt_ctx = NULL;

    // When
    iot_error_t result = _iot_es_mqtt_registration(NULL, mqtt_ctx);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_mqtt_registration_NULL_mqtt_context(void **state)
{
    // Given: NULL MQTT context
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    // Set up some basic context data
    context->lookup_id = REG_TEST_LOOKUP_ID;

    // Add serial numbers
    context->devconf.hashed_sn = REG_TEST_HASHED_SN;

    context->devconf.mnid = REG_TEST_MNID;
    context->devconf.vid = REG_TEST_VID;
    context->devconf.device_type = REG_TEST_DEVICE_TYPE;

    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    // When
    iot_error_t result = _iot_es_mqtt_registration(context, NULL);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);

    // Teardown
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_no_serial_numbers(void **state)
{
    // Given: Context with no serial numbers
    struct iot_context *context = (struct iot_context *)malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    st_mqtt_client mqtt_ctx = (st_mqtt_client)0x12345678;  // Mock MQTT client

    // Set up some basic context data
    context->lookup_id = REG_TEST_LOOKUP_ID;
    context->devconf.mnid = REG_TEST_MNID;
    context->devconf.vid = REG_TEST_VID;
    context->devconf.device_type = REG_TEST_DEVICE_TYPE;

    // Add DIP data
    context->devconf.dip = (struct iot_dip_data *)malloc(sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 0;
    context->devconf.dip->dip_minor_version = 1;

    // When
    iot_error_t result = _iot_es_mqtt_registration(context, mqtt_ctx);

    // Then
    assert_int_equal(result, IOT_ERROR_MEM_ALLOC);

    // Teardown
    free(context->devconf.dip);
    free(context);
}
