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
#include <iot_nv_data.h>
#include <iot_security_util.h>
#include <iot_util.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "TC_MOCK_functions.h"
#include "TC_MOCK_iot_bsp_ble.h"
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

extern void _iot_mqtt_registration_client_callback(st_mqtt_event event, void *event_data, void *user_data);
extern gg_connection_request_status _check_connection_response(struct iot_context *ctx, char *response_payload,
                                                               size_t response_payload_len);
extern iot_error_t _iot_es_mqtt_connect(struct iot_context *ctx, st_mqtt_client target_cli, char *username,
                                        char *sign_data);
extern iot_error_t iot_es_connect(struct iot_context *ctx, int conn_type);
extern iot_error_t iot_es_disconnect(struct iot_context *ctx, int conn_type);
extern iot_error_t iot_update_dip(struct iot_context *ctx, st_mqtt_client mqtt_cli);
extern iot_error_t _iot_es_mqtt_registration(struct iot_context *ctx, st_mqtt_client mqtt_ctx);
extern void _iot_mqtt_signin_client_callback(st_mqtt_event event, void *event_data, void *user_data);
#if !defined(STDK_IOT_CORE_SERIALIZE_CBOR)
extern void *_iot_es_mqtt_registration_json(struct iot_context *ctx, char *dip_id, size_t *msglen);
#endif

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
void TC_STATIC_iot_es_mqtt_registration_success(void **state)
{
    // TODO: test for cbor
}
#else
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

#define DIP_MAJOR_VERSION "0"
#define DIP_MINOR_VERSION "1"
#define DIP_KEY "123e4567-e89b-12d3-a456-426614174000"
#define REG_DEVICE_ID "123e4567-e89b-12d3-a456-426614174000"
#define REG_LOCATION_ID "123e4567-e89b-12d3-a456-426614174000"
void TC_STATIC_iot_es_mqtt_registration_client_callback_SUCCESS(void **state)
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

void TC_STATIC_iot_es_mqtt_registration_client_callback_NULL_context(void **state)
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

void TC_STATIC_iot_es_mqtt_registration_client_callback_NULL_payload(void **state)
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

void TC_STATIC_iot_es_mqtt_registration_client_callback_invalid_event(void **state)
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
    // Use invalid event value (99) to test invalid event handling
    _iot_mqtt_registration_client_callback((st_mqtt_event)99, (void *)&msg, (void *)context);

    // Then: Should not crash
    // This is a void function, so we're just verifying it doesn't crash with invalid event

    // Teardown
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);

    assert_true(true);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_invalid_json(void **state)
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

void TC_STATIC_iot_es_mqtt_registration_client_callback_expired_jwt(void **state)
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

void TC_STATIC_iot_es_mqtt_registration_client_callback_error_event(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_NULL_payload(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_empty_payload(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_invalid_json(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_no_event(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_expired_jwt_no_current_time(void **state)
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

void TC_STATIC_iot_es_mqtt_check_connection_response_unknown_event(void **state)
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

void TC_STATIC_iot_es_mqtt_es_connect_NULL_context(void **state)
{
    // Given: NULL context
    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_connect(NULL, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_mqtt_es_connect_invalid_conn_type(void **state)
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

void TC_STATIC_iot_es_mqtt_es_connect_rate_limit(void **state)
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

void TC_STATIC_iot_es_mqtt_disconnect_NULL_context(void **state)
{
    // Given: NULL context
    int conn_type = IOT_CONNECT_TYPE_REGISTRATION;

    // When
    iot_error_t result = iot_es_disconnect(NULL, conn_type);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_mqtt_disconnect_invalid_conn_type(void **state)
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

void TC_STATIC_iot_es_mqtt_disconnect_no_mqtt_context(void **state)
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

void TC_STATIC_iot_es_mqtt_update_dip_NULL_context(void **state)
{
    // Given: NULL context
    st_mqtt_client mqtt_cli = NULL;

    // When
    iot_error_t result = iot_update_dip(NULL, mqtt_cli);

    // Then
    assert_int_equal(result, IOT_ERROR_INVALID_ARGS);
}

void TC_STATIC_iot_es_mqtt_update_dip_NULL_mqtt_client(void **state)
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

void TC_STATIC_iot_es_mqtt_update_dip_no_dip_data(void **state)
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

/* Local stub used by the tests below for st_mqtt_create */
static void dummy_mqtt_callback(st_mqtt_event event, void *event_data, void *user_data)
{
    (void)event;
    (void)event_data;
    (void)user_data;
}

static int _tc_status_cb_invocations;
static int _tc_status_cb_last_status;
static void _tc_status_cb_test(int status, void *usr_data)
{
    (void)usr_data;
    _tc_status_cb_invocations++;
    _tc_status_cb_last_status = status;
}

void TC_STATIC_iot_es_mqtt_disconnect_communication_with_topics(void **state)
{
    struct iot_context *context;

    // Given: communication client with topic strings + mqtt cli set
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->mqtt_event_topic = strdup("event/topic");
    context->mqtt_health_topic = strdup("health/topic");
    st_mqtt_create(&context->evt_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_non_null(context->evt_mqttcli);

    // When
    iot_error_t result = iot_es_disconnect(context, IOT_CONNECT_TYPE_COMMUNICATION);
    // Then: returns success and clears the fields
    assert_int_equal(result, IOT_ERROR_NONE);
    assert_null(context->mqtt_event_topic);
    assert_null(context->mqtt_health_topic);
    assert_null(context->evt_mqttcli);

    // Teardown
    free(context);
}

void TC_STATIC_iot_es_mqtt_disconnect_registration_with_mqtt(void **state)
{
    struct iot_context *context;

    // Given: registration client set
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    st_mqtt_create(&context->reg_mqttcli, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_non_null(context->reg_mqttcli);

    // When
    iot_error_t result = iot_es_disconnect(context, IOT_CONNECT_TYPE_REGISTRATION);
    // Then
    assert_int_equal(result, IOT_ERROR_NONE);
    assert_null(context->reg_mqttcli);

    // Teardown
    free(context);
}

void TC_STATIC_iot_es_mqtt_update_dip_publish_failure(void **state)
{
    struct iot_context *context;
    st_mqtt_client mqtt_cli;
    iot_error_t result;

    // Given: ctx with a DIP and an mqtt client (publish will fail because not connected)
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->devconf.dip = (struct iot_dip_data *)calloc(1, sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 1;
    context->devconf.dip->dip_minor_version = 2;
    context->devconf.vid = strdup("VIDTEST");
    st_mqtt_create(&mqtt_cli, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_non_null(mqtt_cli);

    // When
    result = iot_update_dip(context, mqtt_cli);
    // Then: with a non-connected mqtt client, publish fails -> non-NONE return
    assert_int_not_equal(result, IOT_ERROR_NONE);

    // Teardown
    st_mqtt_destroy(mqtt_cli);
    free(context->devconf.vid);
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_msg_pre_success(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg = {0};
    char payload[] = "{\"event\":\"connect.success\"}";

    // Given: connection request still pending; callback should run _check_connection_response
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_WAITING;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);

    // When
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);
    // Then: connect.success in pre-success state moves status to SUCCESS
    assert_int_equal(context->sign_in_connection_request_status, GG_CONNECTION_REQUEST_STATUS_SUCCESS);

    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_msg_command_topic_self(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg = {0};
    char payload[] = "{\"commands\":[]}";
    char topic[128];

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    /* deviceId in the topic must match ctx->iot_reg_data.deviceId */
    memcpy(context->iot_reg_data.deviceId, REG_DEVICE_ID, IOT_REG_UUID_STR_LEN);
    snprintf(topic, sizeof(topic), "%s/%s", IOT_SUB_TOPIC_COMMAND_PREFIX, REG_DEVICE_ID);
    msg.topic = topic;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);

    // When: command for the device itself -> dispatches into iot_cap_sub_cb
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_msg_command_topic_unknown(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg = {0};
    char payload[] = "{\"commands\":[]}";
    char topic[128];

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    memcpy(context->iot_reg_data.deviceId, REG_DEVICE_ID, IOT_REG_UUID_STR_LEN);
    /* a different deviceId than the device's own */
    snprintf(topic, sizeof(topic), "%s/00000000-0000-0000-0000-000000000000", IOT_SUB_TOPIC_COMMAND_PREFIX);
    msg.topic = topic;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);

    // When: an unknown deviceId -> walks the (empty) child_device_list
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_msg_notification_topic(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg = {0};
    char payload[] = "{\"event\":\"unknown.event.type\"}";
    char topic[128];

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    snprintf(topic, sizeof(topic), "%s/foo", IOT_SUB_TOPIC_NOTIFICATION_PREFIX);
    msg.topic = topic;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);

    // When: notification topic -> calls iot_noti_sub_cb
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_msg_unknown_topic(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg = {0};
    char payload[] = "{}";
    char topic[] = "/some/other/topic";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_in_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.topic = topic;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);

    // When: unknown topic prefix -> hits the IOT_WARN("No msg delivery handler") branch
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_disconnected_ping_fail(void **state)
{
    struct iot_context *context;
    st_mqtt_evt_dis_reason reason = MQTT_DISCONNECTED_PING_FAIL;

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();

    // When: disconnect with ping-fail reason -> sets ecode CE32 and tries iot_state_update
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_DISCONNECTED, &reason, context);

    /* Teardown */
    {
        device_work_data_t drained;
        while (iot_util_queue_receive(context->work_queue, &drained) == IOT_ERROR_NONE) {
            struct iot_command *cmd = (struct iot_command *)drained.param;
            if (cmd) {
                if (cmd->param)
                    iot_os_free(cmd->param);
                iot_os_free(cmd);
            }
        }
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_disconnected_ping_timeout(void **state)
{
    struct iot_context *context;
    st_mqtt_evt_dis_reason reason = MQTT_DISCONNECTED_PING_TIMEOUT;

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();

    // When: disconnect with ping-timeout -> sets ecode CE33
    _iot_mqtt_signin_client_callback(ST_MQTT_EVENT_DISCONNECTED, &reason, context);

    /* Teardown */
    {
        device_work_data_t drained;
        while (iot_util_queue_receive(context->work_queue, &drained) == IOT_ERROR_NONE) {
            struct iot_command *cmd = (struct iot_command *)drained.param;
            if (cmd) {
                if (cmd->param)
                    iot_os_free(cmd->param);
                iot_os_free(cmd);
            }
        }
    }
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
}

void TC_STATIC_iot_es_mqtt_signin_client_callback_unknown_event(void **state)
{
    struct iot_context *context;

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));

    // When: unknown event -> default branch warning
    _iot_mqtt_signin_client_callback((st_mqtt_event)9999, NULL, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_with_status_cb(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *reg_payload =
        "{\"deviceId\":\"" REG_DEVICE_ID "\",\"locationId\":\"" REG_LOCATION_ID
        "\","
        "\"deviceIntegrationProfileKey\":{\"id\":\"" DIP_KEY "\",\"majorVersion\":0,\"minorVersion\":1}}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    context->status_cb = (void *)_tc_status_cb_test;
    _tc_status_cb_invocations = 0;

    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);
    // Then: status_cb fired with the onboarding-onboarded status
    assert_int_equal(_tc_status_cb_invocations, 1);

    /* Teardown */
    {
        device_work_data_t drained;
        while (iot_util_queue_receive(context->work_queue, &drained) == IOT_ERROR_NONE) {
            struct iot_command *cmd = (struct iot_command *)drained.param;
            if (cmd) {
                if (cmd->param)
                    iot_os_free(cmd->param);
                iot_os_free(cmd);
            }
        }
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    if (context->iot_reg_data.dip)
        iot_os_free(context->iot_reg_data.dip);
    if (context->iot_reg_data.locationId)
        iot_os_free(context->iot_reg_data.locationId);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_expired_jwt_branch(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"event\":\"expired.jwt\",\"currentTime\":1591326145}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->iot_events = iot_os_eventgroup_create();
    context->work_queue_signal = iot_os_eventgroup_create();
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;

    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1591326145);

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    /* Teardown */
    {
        device_work_data_t drained;
        while (iot_util_queue_receive(context->work_queue, &drained) == IOT_ERROR_NONE) {
            struct iot_command *cmd = (struct iot_command *)drained.param;
            if (cmd) {
                if (cmd->param)
                    iot_os_free(cmd->param);
                iot_os_free(cmd);
            }
        }
    }
    iot_os_eventgroup_delete(context->iot_events);
    iot_os_eventgroup_delete(context->work_queue_signal);
    iot_util_queue_delete(context->work_queue);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_error_event_in_payload(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"event\":\"error\"}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_unknown_event_in_payload(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"event\":\"some-other-event\"}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_dip_missing_id(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"deviceIntegrationProfileKey\":{\"majorVersion\":1}}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When: dip without "id" -> error path that frees the malloced reged_dip
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_dip_missing_major(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"deviceIntegrationProfileKey\":{\"id\":\"" DIP_KEY "\"}}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When: dip without majorVersion -> error path
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_dip_missing_minor(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"deviceIntegrationProfileKey\":{\"id\":\"" DIP_KEY "\",\"majorVersion\":3}}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When: dip without minorVersion (optional, default 0) -> success path
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    /* Teardown */
    if (context->iot_reg_data.dip)
        iot_os_free(context->iot_reg_data.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_client_callback_invalid_location(void **state)
{
    struct iot_context *context;
    st_mqtt_msg msg;
    char *payload = "{\"locationId\":\"not-a-uuid\"}";

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->sign_up_connection_request_status = GG_CONNECTION_REQUEST_STATUS_SUCCESS;
    msg.payload = payload;
    msg.payloadlen = strlen(payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;

    // When: invalid location uuid -> takes the iot_util_convert_str_uuid error branch
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, &msg, context);

    free(context);
}

static char _tc_es_connect_device_info[] = {
    "{\n"
    "\t\"deviceInfo\": {\n"
    "\t\t\"firmwareVersion\": \"v1.0\",\n"
    "\t\t\"privateKey\": \"ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8=\",\n"
    "\t\t\"publicKey\": \"BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk=\",\n"
    "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
    "\t}\n"
    "}"};

void TC_STATIC_iot_es_mqtt_es_connect_registration_no_broker(void **state)
{
    struct iot_context *context;
    iot_error_t result;

    /* Given: NV initialised with valid keys + a context with mnid set up so that
     * iot_es_connect can progress past iot_nv_get_serial_number, strdup mnid,
     * and iot_wt_create.  Without a broker URL or server type the connect
     * step will then fail cleanly. */
    iot_error_t err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();
    context->devconf.mnid = REG_TEST_MNID;
    context->server_env = SERVER_ENV_UNKNOWN; /* forces the "url does not exist" branch */

    /* When */
    result = iot_es_connect(context, IOT_CONNECT_TYPE_REGISTRATION);
    /* Then: not NONE because no broker is reachable */
    assert_int_not_equal(result, IOT_ERROR_NONE);

    /* Teardown */
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_es_connect_registration_unknown_server(void **state)
{
    struct iot_context *context;
    iot_error_t result;
    iot_error_t err;

    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();
    context->devconf.mnid = REG_TEST_MNID;
    /* server_type past EU_WEST1 hits the default branch in _iot_es_set_broker_url_port */
    context->server_env = (server_env_type)(SERVER_ENV_DEV + 1);

    /* When */
    result = iot_es_connect(context, IOT_CONNECT_TYPE_REGISTRATION);
    /* Then */
    assert_int_not_equal(result, IOT_ERROR_NONE);

    /* Teardown */
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_es_connect_communication_no_reg(void **state)
{
    struct iot_context *context;
    iot_error_t err;

    /* Given: communication mode but iot_reg_data.updated == false short-circuits */
    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();
    context->devconf.mnid = REG_TEST_MNID;
    context->iot_reg_data.updated = false;

    /* When: drive the registration-not-yet-updated short-circuit branch */
    (void)iot_es_connect(context, IOT_CONNECT_TYPE_COMMUNICATION);
    /* Then: function returns without crashing (covers the goto-out path) */

    /* Teardown */
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_es_connect_communication_with_reg_no_broker(void **state)
{
    struct iot_context *context;
    iot_error_t err;

    /* Given: communication path with iot_reg_data.updated=true so we proceed
     * past the user-id check.  The mqtt_connect step then fails because no
     * broker is reachable, exercising the create+connect+goto-out lines. */
    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    context->work_queue_signal = iot_os_eventgroup_create();
    context->devconf.mnid = REG_TEST_MNID;
    context->iot_reg_data.updated = true;
    memcpy(context->iot_reg_data.deviceId, REG_DEVICE_ID, IOT_REG_UUID_STR_LEN);
    /* No broker_url and SERVER_TYPE_UNKNOWN -> _iot_es_mqtt_connect fails with INVALID_ARGS */
    context->server_env = SERVER_ENV_UNKNOWN;

    /* When */
    (void)iot_es_connect(context, IOT_CONNECT_TYPE_COMMUNICATION);
    /* Then: returns without crashing */

    /* Teardown */
    if (context->mqtt_event_topic)
        free(context->mqtt_event_topic);
    if (context->mqtt_health_topic)
        free(context->mqtt_health_topic);
    iot_util_queue_delete(context->work_queue);
    iot_os_eventgroup_delete(context->work_queue_signal);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_registration_publish_path(void **state)
{
    struct iot_context *context;
    st_mqtt_client mqtt_ctx;

    /* Given: a valid context (with hashed_sn etc.) and a real mqtt_client.
     * The publish will fail because the client isn't connected, but the test
     * exercises the JSON-build, malloc-dip-id, publish-error and JSON-free
     * branches of _iot_es_mqtt_registration. */
    context = generate_es_mqtt_registration_context(true, false);
    st_mqtt_create(&mqtt_ctx, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_non_null(mqtt_ctx);

    /* When */
    iot_error_t result = _iot_es_mqtt_registration(context, mqtt_ctx);
    /* Then: not NONE because the disconnected publish fails */
    assert_int_not_equal(result, IOT_ERROR_NONE);

    /* Teardown */
    st_mqtt_destroy(mqtt_ctx);
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_update_dip_publish_path(void **state)
{
    struct iot_context *context;
    st_mqtt_client mqtt_cli;

    /* Given: ctx with dip, vid, plus a real mqtt_client.  Publish will fail
     * but the JSON-construction + cleanup path is exercised. */
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->devconf.dip = (struct iot_dip_data *)calloc(1, sizeof(struct iot_dip_data));
    iot_util_convert_str_uuid(REG_TEST_DIP_ID, &context->devconf.dip->dip_id);
    context->devconf.dip->dip_major_version = 4;
    context->devconf.dip->dip_minor_version = 0;
    context->devconf.vid = REG_TEST_VID;
    st_mqtt_create(&mqtt_cli, dummy_mqtt_callback, NULL, NULL, NULL);

    /* When */
    iot_error_t result = iot_update_dip(context, mqtt_cli);
    /* Then */
    assert_int_not_equal(result, IOT_ERROR_NONE);

    /* Teardown */
    st_mqtt_destroy(mqtt_cli);
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_json_with_location_room(void **state)
{
    /* Cover the optional cloud.location, cloud.label and cloud.room branches
     * of _iot_es_mqtt_registration_json. */
    struct iot_context *context;
    char *result;
    size_t msglen = 0;

    context = generate_es_mqtt_registration_context(false, false);
    context->prov_data.cloud.location = REG_TEST_LOCATION_ID;
    context->prov_data.cloud.label = REG_TEST_LABEL;
    context->prov_data.cloud.room = REG_TEST_ROOM_ID;

    result = _iot_es_mqtt_registration_json(context, NULL, &msglen);
    assert_non_null(result);
    assert_int_not_equal(msglen, 0);

    /* Teardown */
    free(result);
    free(context->devconf.dip);
    free(context);
}

void TC_STATIC_iot_es_mqtt_registration_json_with_combo_sn(void **state)
{
    /* combo_sn-set path frees combo_sn after use (lines 717-719). */
    struct iot_context *context;
    char *result;
    size_t msglen = 0;
    char dip_id[40] = "00000000-0000-0000-0000-000000000000";

    context = generate_es_mqtt_registration_context(false, true /* serial_type */);

    result = _iot_es_mqtt_registration_json(context, dip_id, &msglen);
    assert_non_null(result);
    assert_int_not_equal(msglen, 0);
    assert_null(context->devconf.combo_sn); /* freed inside */

    /* Teardown */
    free(result);
    free(context->devconf.dip);
    free(context);
}

static void _tc_install_connack_stream(unsigned char *buffer, size_t buffer_size)
{
    /* Build a CONNACK response (Solace MQTT 3.1.1 Conformance Spec):
     *   byte 0: 0x20 = CONNACK fixed header
     *   byte 1: 0x02 = remaining length
     *   byte 2: 0x00 = no session present
     *   byte 3: 0x00 = "connection accepted" return code
     */
    assert_true(buffer_size >= 4);
    buffer[0] = 0x20;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = 0x00;
    port_net_mock_reset_read_stream(buffer, 4);
    port_net_mock_reset_socket_status(1);
}

void TC_STATIC_iot_es_mqtt_connect_success_path(void **state)
{
    struct iot_context *context;
    st_mqtt_client mqtt_cli;
    iot_error_t result;
    iot_error_t err;
    unsigned char connack_buf[8];

    /* Given: NV initialised, fake root cert via BLE-mock wrap, mocked CONNACK */
    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->prov_data.cloud.broker_url = strdup("test.example.com");
    context->prov_data.cloud.broker_port = 8883;
    err = st_mqtt_create(&mqtt_cli, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_int_equal(err, 0);
    tc_mock_ble_set_get_certificate_use_wrap(1);
    _tc_install_connack_stream(connack_buf, sizeof(connack_buf));
    expect_any(__wrap_port_net_write, len);
    expect_any(__wrap_port_net_write, buf);

    /* When */
    result = _iot_es_mqtt_connect(context, mqtt_cli, "user@test", "fake-token");
    /* Then: with the CONNACK stream, the connect step itself succeeds */
    assert_int_equal(result, IOT_ERROR_NONE);

    /* Teardown */
    tc_mock_ble_set_get_certificate_use_wrap(0);
    port_net_mock_reset_read_stream(NULL, 0);
    st_mqtt_destroy(mqtt_cli);
    free(context->prov_data.cloud.broker_url);
    free(context);
    iot_nv_deinit();
}

static void _tc_install_connack_rc_stream(unsigned char *buffer, size_t buffer_size, unsigned char rc)
{
    assert_true(buffer_size >= 4);
    buffer[0] = 0x20;
    buffer[1] = 0x02;
    buffer[2] = 0x00;
    buffer[3] = rc;
    port_net_mock_reset_read_stream(buffer, 4);
    port_net_mock_reset_socket_status(1);
}

static void _tc_run_es_mqtt_connect_with_connack_rc(unsigned char rc)
{
    struct iot_context *context;

    st_mqtt_client mqtt_cli;
    iot_error_t err;
    unsigned char buf[8];

    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);

    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->prov_data.cloud.broker_url = strdup("test.example.com");
    context->prov_data.cloud.broker_port = 8883;
    err = st_mqtt_create(&mqtt_cli, dummy_mqtt_callback, NULL, NULL, NULL);
    assert_int_equal(err, 0);
    tc_mock_ble_set_get_certificate_use_wrap(1);
    _tc_install_connack_rc_stream(buf, sizeof(buf), rc);
    expect_any(__wrap_port_net_write, len);
    expect_any(__wrap_port_net_write, buf);

    /* When */
    (void)_iot_es_mqtt_connect(context, mqtt_cli, "user@test", "fake-token");
    /* Then: just verify it returns without crashing - rc-specific branch is exercised */

    /* Teardown */
    tc_mock_ble_set_get_certificate_use_wrap(0);
    port_net_mock_reset_read_stream(NULL, 0);
    st_mqtt_destroy(mqtt_cli);
    free(context->prov_data.cloud.broker_url);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_connect_unacceptable_protocol(void **state)
{
    /* connack rc=0x01 -> E_ST_MQTT_UNNACCEPTABLE_PROTOCOL -> IOT_ERROR_MQTT_SERVER_UNAVAIL */
    _tc_run_es_mqtt_connect_with_connack_rc(0x01);
}

void TC_STATIC_iot_es_mqtt_connect_server_unavailable(void **state)
{
    /* connack rc=0x03 -> E_ST_MQTT_SERVER_UNAVAILABLE */
    _tc_run_es_mqtt_connect_with_connack_rc(0x03);
}

void TC_STATIC_iot_es_mqtt_connect_clientid_rejected(void **state)
{
    /* connack rc=0x02 -> E_ST_MQTT_CLIENTID_REJECTED -> retry path or REJECT_CONNECT */
    _tc_run_es_mqtt_connect_with_connack_rc(0x02);
}

void TC_STATIC_iot_es_mqtt_connect_bad_credentials(void **state)
{
    /* connack rc=0x04 -> E_ST_MQTT_BAD_USERNAME_OR_PASSWORD */
    _tc_run_es_mqtt_connect_with_connack_rc(0x04);
}

void TC_STATIC_iot_es_mqtt_connect_not_authorized(void **state)
{
    /* connack rc=0x05 -> E_ST_MQTT_NOT_AUTHORIZED */
    _tc_run_es_mqtt_connect_with_connack_rc(0x05);
}

void TC_STATIC_iot_es_mqtt_connect_critical_reject_max(void **state)
{
    struct iot_context *context;
    st_mqtt_client mqtt_cli;
    iot_error_t err;
    unsigned char buf[8];
    int i;

    /* Repeatedly fail with rc=0x05 to push critical_reject_count past
     * IOT_MQTT_CONNECT_CRITICAL_REJECT_MAX so the REJECT_CONNECT branch is hit. */
    err = iot_nv_init((unsigned char *)_tc_es_connect_device_info, strlen(_tc_es_connect_device_info));
    assert_int_equal(err, IOT_ERROR_NONE);
    context = (struct iot_context *)calloc(1, sizeof(struct iot_context));
    context->prov_data.cloud.broker_url = strdup("test.example.com");
    context->prov_data.cloud.broker_port = 8883;
    /* manually push count to one less than the threshold */
    context->mqtt_connect_critical_reject_count = 100;

    for (i = 0; i < 1; i++) {
        st_mqtt_create(&mqtt_cli, dummy_mqtt_callback, NULL, NULL, NULL);
        tc_mock_ble_set_get_certificate_use_wrap(1);
        _tc_install_connack_rc_stream(buf, sizeof(buf), 0x05);
        expect_any(__wrap_port_net_write, len);
        expect_any(__wrap_port_net_write, buf);
        (void)_iot_es_mqtt_connect(context, mqtt_cli, "user@test", "fake-token");
        tc_mock_ble_set_get_certificate_use_wrap(0);
        port_net_mock_reset_read_stream(NULL, 0);
        st_mqtt_destroy(mqtt_cli);
    }

    free(context->prov_data.cloud.broker_url);
    free(context);
    iot_nv_deinit();
}

void TC_STATIC_iot_es_mqtt_check_connection_response_expired_jwt_with_current_time(void **state)
{
    /* Given: Expired JWT with currentTime present — exercises the
     * iot_bsp_system_set_time_in_sec path and returns FAIL. */
    char *response_payload = "{\"event\":\"expired.jwt\",\"currentTime\":1598246160}";
    size_t response_payload_len = strlen(response_payload);
    struct iot_context ctx = {
        0,
    };

    /* When */
    expect_value(__wrap_iot_bsp_system_set_time_in_sec, time_in_sec, 1598246160);
    gg_connection_request_status result = _check_connection_response(&ctx, response_payload, response_payload_len);

    /* Then */
    assert_int_equal(result, GG_CONNECTION_REQUEST_STATUS_FAIL);
}

void TC_STATIC_iot_es_mqtt_connect_unknown_error(void **state)
{
    /* connack rc=0x06 -> _iot_mqtt_convert_return_code default ->
     * E_ST_MQTT_FAILURE -> default case in _iot_es_mqtt_connect switch */
    _tc_run_es_mqtt_connect_with_connack_rc(0x06);
}
