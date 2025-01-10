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
#include <stdbool.h>
#include <iot_main.h>
#include <iot_internal.h>
#include <iot_nv_data.h>
#include <iot_easysetup.h>
#include <iot_util.h>
#include <iot_capability.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

#define TEST_FIRMWARE_VERSION "testFirmwareVersion"
#define TEST_DEVICE_PUBLIC_B64_KEY "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
#define TEST_DEVICE_SECRET_B64_KEY "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define TEST_DEVICE_SERIAL_NUMBER "STDKtESt7968d226"
static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \""TEST_FIRMWARE_VERSION"\",\n"
        "\t\t\"privateKey\": \""TEST_DEVICE_SECRET_B64_KEY"\",\n"
        "\t\t\"publicKey\": \""TEST_DEVICE_PUBLIC_B64_KEY"\",\n"
        "\t\t\"serialNumber\": \""TEST_DEVICE_SERIAL_NUMBER"\"\n"
        "\t}\n"
        "}"
};

static char wrong_device_info_no_firmwareVersion[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"privateKey\": \""TEST_DEVICE_SECRET_B64_KEY"\",\n"
        "\t\t\"publicKey\": \""TEST_DEVICE_PUBLIC_B64_KEY"\",\n"
        "\t\t\"serialNumber\": \""TEST_DEVICE_SERIAL_NUMBER"\"\n"
        "\t}\n"
        "}"
};

#define TEST_ONBOARDING_MNID    "fTST"
#define TEST_ONBOARDING_SETUPID "001"
#define TEST_ONBOARDING_VID "STDK_BULB_0001"
#define TEST_ONBOARDING_DEVICETYPEID    "Switch"

static char sample_onboarding_config[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \""TEST_ONBOARDING_MNID"\",\n"
        "    \"setupId\": \""TEST_ONBOARDING_SETUPID"\",\n"
        "    \"vid\": \""TEST_ONBOARDING_VID"\",\n"
        "    \"deviceTypeId\": \""TEST_ONBOARDING_DEVICETYPEID"\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"BUTTON\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\"\n"
        "  }\n"
        "}"
};

static char wrong_onboarding_config_no_mnId[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"BUTTON\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\"\n"
        "  }\n"
        "}"
};

void TC_st_conn_init_null_parameters(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: all parameters are null
    // When
    context = st_conn_init(NULL, 0, NULL, 0);
    // Then
    assert_null(context);

    // Given: null device_info
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), NULL, 0);
    // Then
    assert_null(context);

    // Given: null onboarding_config
    // When
    context = st_conn_init(NULL, 0, sample_device_info, sizeof(sample_device_info));
    // Then
    assert_null(context);
}

void TC_st_conn_init_malloc_failure(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: malloc failure
    set_mock_iot_os_malloc_failure();
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), sample_device_info, sizeof(sample_device_info));
    // Then
    assert_null(context);

    //Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

void TC_st_conn_init_wrong_onboarding_config(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: wrong onboarding config
    // When
    context = st_conn_init(wrong_onboarding_config_no_mnId, sizeof(wrong_onboarding_config_no_mnId), sample_device_info, sizeof(sample_device_info));
    // Then
    assert_null(context);
}

void TC_st_conn_init_wrong_device_info(void **state)
{
    IOT_CTX *context;
    UNUSED(state);

    // Given: wrong device info
    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), wrong_device_info_no_firmwareVersion, sizeof(wrong_device_info_no_firmwareVersion));
    // Then
    assert_null(context);
}

void TC_st_conn_init_success(void **state)
{
    IOT_CTX *context;
    struct iot_context *internal_context;
    size_t count = 0;
    UNUSED(state);

    // When
    context = st_conn_init(sample_onboarding_config, sizeof(sample_onboarding_config), sample_device_info, sizeof(sample_device_info));
    // Then
    assert_non_null(context);
    internal_context = (struct iot_context*) context;
    assert_string_equal(internal_context->devconf.mnid, TEST_ONBOARDING_MNID);
    assert_string_equal(internal_context->devconf.vid, TEST_ONBOARDING_VID);
    assert_string_equal(internal_context->devconf.setupid, TEST_ONBOARDING_SETUPID);
    assert_string_equal(internal_context->devconf.device_type, TEST_ONBOARDING_DEVICETYPEID);
    assert_int_equal(internal_context->devconf.pk_type, IOT_SECURITY_KEY_TYPE_ED25519);
    assert_string_equal(internal_context->device_info.firmware_version, TEST_FIRMWARE_VERSION);
    assert_non_null(internal_context->work_queue);
    assert_non_null(internal_context->usr_events);
    assert_non_null(internal_context->iot_events);
    assert_non_null(internal_context->work_queue_thread);
    //Teardown
    iot_os_eventgroup_set_bits(internal_context->work_queue_signal, DEVICE_WORK_QUEUE_KILL_SIGNAL);
    while (internal_context->work_queue_thread && count < 100) {
        iot_os_delay(50);
        count++;
    }
    if (internal_context->work_queue_thread) {
        print_error("Failed to kill work queue thread\n");
        return;
    }
    iot_os_mutex_destroy(&internal_context->st_conn_lock);
    iot_os_eventgroup_delete(internal_context->work_queue_signal);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_util_queue_delete(internal_context->work_queue);
    iot_api_device_info_mem_free(&internal_context->device_info);
    iot_api_onboarding_config_mem_free(&internal_context->devconf);
    iot_nv_deinit();
    iot_os_free(internal_context);
}

void TC_st_conn_cleanup_invalid_parameters(void **state)
{
    IOT_CTX *context;
    int err;
    UNUSED(state);

    // When: Null iot_ctx
    err = st_conn_cleanup(NULL, false);
    // Then
    assert_int_not_equal(err, 0);

    // Given: empty context
    context = (IOT_CTX*) malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    // When: empty iot_ctx
    err = st_conn_cleanup(context, false);
    // Then
    assert_int_not_equal(err, 0);
    // Teardown
    free(context);
}

void TC_st_conn_cleanup_success(void **state)
{
    IOT_CTX *context;
    struct iot_context *internal_context;
    int err;
    iot_os_thread test_thread;
    UNUSED(state);

    // Given
    internal_context = malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *) internal_context;
    internal_context->work_queue = iot_util_queue_create(sizeof(device_work_data_t));
    assert_non_null(internal_context->work_queue);
    internal_context->usr_events = iot_os_eventgroup_create();
    assert_non_null(internal_context->usr_events);
    internal_context->iot_events = iot_os_eventgroup_create();
    assert_non_null(internal_context->iot_events);
    err = iot_os_mutex_init(&internal_context->st_conn_lock);
    assert_int_equal(err, IOT_OS_TRUE);
    // When: Null iot_ctx
    err = st_conn_cleanup(context, false);
    // Then
    assert_return_code(err, 0);
    // Teardown
    iot_util_queue_delete(internal_context->work_queue);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_mutex_destroy(&internal_context->st_conn_lock);
    free(internal_context);
}

extern iot_error_t _create_easysetup_resources(struct iot_context *ctx, iot_pin_t *pin_num);
extern void _delete_easysetup_resources_all(struct iot_context *ctx);

void TC_easysetup_resources_create_delete_success(void** state)
{
    iot_error_t err;
    struct iot_context *context;
    UNUSED(state);

    set_mock_detect_memory_leak(true);
    // Given: pin type context
    iot_pin_t pin = { .pin = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 } };
    context = (struct iot_context *) calloc(1, sizeof(struct iot_context));
    context->devconf.ownership_validation_type = IOT_OVF_TYPE_PIN;

    // When: create resource
    err = _create_easysetup_resources(context, &pin);
    // Then: success and has proper resources
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&pin.pin, context->pin, sizeof(iot_pin_t));
    assert_non_null(context->easysetup_security_context);
    assert_non_null(context->easysetup_resp_queue);
    assert_true(context->es_res_created);

    // When: delete resource
    _delete_easysetup_resources_all(context);
    // Then: verify deletion
    assert_null(context->pin);
    assert_null(context->easysetup_security_context);
    assert_null(context->easysetup_resp_queue);
    assert_false(context->es_res_created);

    set_mock_detect_memory_leak(false);
}

extern iot_error_t _check_prov_data_validation(struct iot_device_prov_data *prov_data);

struct _prov_test_data {
    iot_error_t expected;
    char *ssid;
    char *url;
    int num;
};

static struct iot_device_prov_data *_generate_test_prov_data(struct _prov_test_data data)
{
    struct iot_device_prov_data *prov_data;
    struct iot_wifi_prov_data *wifi_prov;
    struct iot_cloud_prov_data *cloud_prov;

    prov_data = (struct iot_device_prov_data *) calloc(1, sizeof(struct iot_device_prov_data));
    assert_non_null(prov_data);
    wifi_prov = &prov_data->wifi;
    cloud_prov = &prov_data->cloud;
    if (data.ssid) {
        strncpy(wifi_prov->ssid, data.ssid, sizeof(wifi_prov->ssid) -  1);
    }
    if (data.url) {
        cloud_prov->broker_url = strdup(data.url);
    }

    cloud_prov->broker_port = data.num;

    return prov_data;
}

void TC_check_prov_data_validation(void **state)
{
    iot_error_t err;
    struct _prov_test_data test_set[] = {
            { IOT_ERROR_NONE, "TestSsid", "test.domain.com", 443},
            { IOT_ERROR_INVALID_ARGS, NULL, "test.domain.com", 443},
            { IOT_ERROR_INVALID_ARGS, "TestSsid", NULL, 443},
            { IOT_ERROR_INVALID_ARGS, "TestSsid", "test.domain.com", -5},
    };

    for (int i = 0; i < sizeof(test_set)/sizeof(struct _prov_test_data); i++) {
        // Given
        struct iot_device_prov_data *prov_data = _generate_test_prov_data(test_set[i]);
        // When
        err = _check_prov_data_validation(prov_data);
        // Then
        assert_int_equal(err, test_set[i].expected);
        // Teardown
        free(prov_data);
    }
}
