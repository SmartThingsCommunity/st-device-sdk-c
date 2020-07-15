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

void TC_STATIC_iot_es_mqtt_registration_success(void **state)
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
    } else {
        assert_null(JSON_GET_OBJECT_ITEM(root, "firmwareVersion"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "modelNumber"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "marketingName"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "manufacturerName"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "manufacturerCode"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "osType"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "osVersion"));
        assert_null(JSON_GET_OBJECT_ITEM(root, "stdkVersion"));
    }

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
#endif