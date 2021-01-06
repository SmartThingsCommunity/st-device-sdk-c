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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <iot_main.h>
#include <security/iot_security_helper.h>
#include <iot_util.h>
#include <external/JSON.h>
#include <iot_internal.h>

#define REG_TEST_LOOKUP_ID "c37e0475-b727-49ca-bdfe-33bda78c28a7";
#define REG_TEST_LOCATION_ID "9400c47a-5d29-452c-bb36-0a44c08eba19";
#define REG_TEST_ROOM_ID "7be9ec0b-8819-44f9-ac26-2f4e46f48731"
#define REG_TEST_DIP_ID "2154ccfc-84d1-432f-8c0d-5651b5a0da8e"
#define REG_TEST_HASHED_SN "VNZCGRB2VIt+4QckH7OWZPp8UxulH/nZDCDgXpPHr1M" //stdktest00000001
#define REG_TEST_LABEL "testLabel"
#define REG_TEST_MNID   "fTST"
#define REG_TEST_VID    "TEST_VID"
#define REG_TEST_DEVICE_TYPE    "Light"
#define REG_TEST_DIP_ID "2154ccfc-84d1-432f-8c0d-5651b5a0da8e"
#define REG_TEST_FW_VERSION "testFirmware"
#define REG_TEST_MODEL_NUMBER "testModel"
#define REG_TEST_MARKETING_NAME "testMarketingName"
#define REG_TEST_MANUFACTURER_NAME  "testManufacturerName"
#define REG_TEST_MANUFACTURER_CODE  "testManufacturerCode"

#if defined(STDK_IOT_CORE_SERIALIZE_CBOR)
void TC_STATIC_iot_es_mqtt_registration_success(void **state)
{
    //TODO: test for cbor
}
#else
extern void *_iot_es_mqtt_registration_json(struct iot_context *ctx, char *dip_id, size_t *msglen, bool self_reged);
static void
assert_es_mqtt_registration_json(struct iot_context *context, char *payload, size_t msglen, bool self_reged);
static struct iot_context *generate_es_mqtt_registration_context(bool use_opt, bool use_d2d);
struct registration_test_condition {
    bool use_opt;
    bool use_d2d;
};

void TC_STATIC_iot_es_mqtt_registration_SUCCESS(void **state)
{
    char *output_str;
    size_t msglen;
    struct iot_context *context;
    char *dip_id = REG_TEST_DIP_ID;
    struct registration_test_condition condition[4] = {
        {false, false}, {false, true},
        {true, false}, {true, true}
    };

    for (int i = 0; i < 4; i++) {
        // Given
        context = generate_es_mqtt_registration_context(condition[i].use_opt, condition[i].use_d2d);
        // When
        output_str = _iot_es_mqtt_registration_json(context, dip_id, &msglen, condition[i].use_d2d);
        // Then
        assert_es_mqtt_registration_json(context, output_str, msglen, condition[i].use_d2d);
        // Teardown
        free(output_str);
        free(context->devconf.dip);
        free(context);
    }

}

struct iot_context *generate_es_mqtt_registration_context(bool use_opt, bool use_d2d)
{
    struct iot_context *context;
    struct iot_devconf_prov_data *devconf;
    struct iot_device_info *dev_info;

    context = (struct iot_context *) malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));

    context->lookup_id = REG_TEST_LOOKUP_ID;
    if (use_d2d) {
        context->prov_data.cloud.location = REG_TEST_LOCATION_ID;
        context->prov_data.cloud.room = REG_TEST_ROOM_ID;
        context->prov_data.cloud.label = REG_TEST_LABEL;
    }

    devconf = &context->devconf;
    devconf->hashed_sn = REG_TEST_HASHED_SN;
    devconf->mnid = REG_TEST_MNID;
    devconf->vid = REG_TEST_VID;
    devconf->device_type = REG_TEST_DEVICE_TYPE;
    devconf->dip = (struct iot_dip_data*) malloc(sizeof(struct iot_dip_data));
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

void assert_es_mqtt_registration_json(struct iot_context *context, char *payload, size_t msglen, bool self_reged)
{
    JSON_H *root;

    assert_non_null(context);
    assert_non_null(payload);
    assert_int_equal(strlen(payload), msglen);

    root = JSON_PARSE(payload);
    assert_string_equal(context->lookup_id,
                        JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "lookupId")));
    if (context->prov_data.cloud.location) {
        assert_string_equal(context->prov_data.cloud.location,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "locationId")));
    }
    if (context->prov_data.cloud.room && self_reged == false) {
        assert_string_equal(context->prov_data.cloud.room,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "roomId")));
    } else if (self_reged == false) {
        assert_string_equal(context->devconf.hashed_sn,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "serialHash")));
        assert_non_null(JSON_GET_OBJECT_ITEM(root, "provisioningTs"));
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "serialHash"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "provisioningTs"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "roomId"));
    }

    if (context->prov_data.cloud.label) {
        assert_string_equal(context->prov_data.cloud.label,
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "label")));
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
        assert_string_equal(iot_os_get_os_name(),
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "osType")));
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "osType"));
    }

    if (iot_os_get_os_version_string()) {
        assert_string_equal(iot_os_get_os_version_string(),
                            JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "osVersion")));;
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "osVersion"));
    }
    assert_string_equal(STDK_VERSION_STRING,
                        JSON_GET_STRING_VALUE(JSON_GET_OBJECT_ITEM(root, "stdkVersion")));

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
            "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switch\",\"attribute\":\"switch\",\"value\":\"on\",\"providerData\":{\"sequenceNumber\":1,\"timestamp\":\"1598246160400\"}}]}",
            "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switchLevel\",\"attribute\":\"level\",\"value\":50,\"unit\":\"%\",\"providerData\":{\"sequenceNumber\":2,\"timestamp\":\"1598246160419\"}}]}",
            "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"colorTemperature\",\"attribute\":\"colorTemperature\",\"value\":2000,\"providerData\":{\"sequenceNumber\":3,\"timestamp\":\"1598246160437\"}}]}"
    };
    int expected_sequence_num[3] = { 1, 2, 3 };

    for (int i = 0; i < 3; i++) {
        int seq = _iot_parse_sequence_num((char *) mqtt_payload[i]);
        assert_int_equal(seq, expected_sequence_num[i]);
    }
}

void TC_STATIC_iot_parse_sequence_num_FAILURE(void **state)
{
    const char *mqtt_payload[4] = {
            NULL,
            "{}",
            "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"switch\",\"attribute\":\"switch\",\"value\":\"on\"}]}",
            "{\"deviceEvents\":[{\"component\":\"main\",\"capability\":\"colorTemperature\",\"attribute\":\"colorTemperature\",\"value\":2000,\"providerData\":{\"timestamp\":\"1598246160437\"}}]}"
    };

    for (int i = 0; i < 4; i++) {
        int seq = _iot_parse_sequence_num((char *) mqtt_payload[i]);
        assert_int_equal(seq, 0);
    }
}

#define DIP_MAJOR_VERSION   "0"
#define DIP_MINOR_VERSION   "1"
#define DIP_KEY "123e4567-e89b-12d3-a456-426614174000"
#define REG_DEVICE_ID "123e4567-e89b-12d3-a456-426614174000"
#define REG_LOCATION_ID "123e4567-e89b-12d3-a456-426614174000"
extern void _iot_mqtt_registration_client_callback(st_mqtt_event event, void *event_data, void *user_data);

void TC_STATIC_iot_mqtt_registration_client_callback_SUCCESS(void **state)
{
    st_mqtt_msg msg;
    struct iot_uuid uuid;
    struct iot_context *context;
    char *reg_payload = "{\"deviceId\":\""REG_DEVICE_ID"\",\n"
                              "\"name\":\"Light\",\n"
                              "\"label\":\"Light\",\n"
                              "\"locationId\":\""REG_LOCATION_ID"\",\n"
                              "\"roomId\":\"123e4567-e89b-12d3-a456-426614174000\",\n"
                              "\"type\":\"MQTT\",\n"
                              "\"deviceIntegrationProfileKey\":{\"id\":\""DIP_KEY"\",\"majorVersion\":"DIP_MAJOR_VERSION",\"minorVersion\":"DIP_MINOR_VERSION"},\n"
                              "\"routingKey\":\"us\",\n"
                              "\"metadata\":{\"serialNumber\":\"SERIALNUMBER\",\"mnId\":\"MNID\",\"vid\":\"VIDTEST\",\"deviceTypeId\":\"Light\",\n"
                              "             \"lookupId\":\"bb000ddd-92a0-42a3-86f0-b531f278af06\",\"registrationPayloadType\":\"json\",\"stack\":\"K8\",\n"
                              "             \"serialHash\":\"rpSpVp9nOkPowHrwBzA6UqyC48cJdYyBpyfZFqbZeh0\",\"provisioningTs\":1598256474,\n"
                              "             \"manufacturerName\":\"Opensource\",\"manufacturerCode\":\"101\",\"marketingName\":\"Light Device\",\n"
                              "             \"modelNumber\":\"TEST\",\"firmwareVersion\":\"1.3.6\",\"osType\":\"FreeRTOS\",\"osVersion\":\"V8.2.0\",\"stdkVersion\":\"1.3.6\"}}";

    // Given
    context = (struct iot_context*) malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH, sizeof(struct iot_command));
    context->iot_events = iot_os_eventgroup_create();

    msg.payload = reg_payload;
    msg.payloadlen = strlen(reg_payload);
    msg.topic = IOT_SUB_TOPIC_REGISTRATION_PREFIX;
    // When
    _iot_mqtt_registration_client_callback(ST_MQTT_EVENT_MSG_DELIVERED, (void*) &msg, (void *)context);

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
    iot_os_queue_delete(context->cmd_queue);
    iot_os_free(context->iot_reg_data.dip);
    iot_os_free(context->iot_reg_data.locationId);
    free(context);
}

#endif