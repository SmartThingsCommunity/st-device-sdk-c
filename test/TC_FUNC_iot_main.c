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
#include <iot_main.h>
#include <iot_internal.h>
#include <iot_nv_data.h>
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
    assert_int_equal(internal_context->devconf.pk_type, IOT_CRYPTO_PK_ED25519);
    assert_string_equal(internal_context->device_info.firmware_version, TEST_FIRMWARE_VERSION);
    assert_non_null(internal_context->state_timer);
    assert_non_null(internal_context->cmd_queue);
    assert_non_null(internal_context->usr_events);
    assert_non_null(internal_context->pub_queue);
    assert_non_null(internal_context->iot_events);
    assert_non_null(internal_context->main_thread);
    //Teardown
    iot_os_thread_delete(internal_context->main_thread);
    iot_os_eventgroup_delete(internal_context->iot_events);
    iot_os_queue_delete(internal_context->pub_queue);
    iot_os_eventgroup_delete(internal_context->usr_events);
    iot_os_queue_delete(internal_context->cmd_queue);
    iot_api_device_info_mem_free(&internal_context->device_info);
    iot_api_onboarding_config_mem_free(&internal_context->devconf);
    iot_nv_deinit();
    iot_os_timer_destroy(&internal_context->state_timer);
    iot_os_free(internal_context);
}

void TC_st_conn_cleanup_invalid_parameters(void **state)
{
    IOT_CTX *context;
    int err;
    UNUSED(state);

    // When: Null iot_ctx and reboot true
    err = st_conn_cleanup(NULL, true);
    // Then
    assert_int_not_equal(err, 0);

    // When: Null iot_ctx
    err = st_conn_cleanup(NULL, false);
    // Then
    assert_int_not_equal(err, 0);

    // Given: empty context
    context = (IOT_CTX*) malloc(sizeof(struct iot_context));
    memset(context, '\0', sizeof(struct iot_context));
    // When: Null iot_ctx
    err = st_conn_cleanup(context, true);
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
    UNUSED(state);

    // Given
    internal_context = malloc(sizeof(struct iot_context));
    assert_non_null(internal_context);
    memset(internal_context, '\0', sizeof(struct iot_context));
    context = (IOT_CTX *) internal_context;
    internal_context->cmd_queue = iot_os_queue_create(IOT_QUEUE_LENGTH,
                                         sizeof(struct iot_command));
    assert_non_null(internal_context->cmd_queue);
    internal_context->iot_events = iot_os_eventgroup_create();
    assert_non_null(internal_context->iot_events);
    expect_any(__wrap_iot_os_delay, delay_ms);
    // When: Null iot_ctx
    err = st_conn_cleanup(context, true);
    // Then
    assert_return_code(err, 0);
    // Teardown
    iot_os_queue_delete(internal_context->cmd_queue);
    iot_os_eventgroup_delete(internal_context->iot_events);
    free(internal_context);
}