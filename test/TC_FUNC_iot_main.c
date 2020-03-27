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

static char sample_onboarding_config[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
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