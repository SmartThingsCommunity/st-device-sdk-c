/* ***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include <string.h>
#include <iot_error.h>
#include <iot_easysetup.h>
#include <iot_nv_data.h>
#include <iot_internal.h>
#include "TC_MOCK_functions.h"

static char sample_device_info[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
        "\t\t\"privateKey\": \"ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8=\",\n"
        "\t\t\"publicKey\": \"BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk=\",\n"
        "\t\t\"serialNumber\": \"STDKtESt7968d226\"\n"
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

static const char sample_ssid[] = "STDK_E4fTST0016LWpcd226";

int TC_iot_easysetup_create_ssid_setup(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data *devconf;
#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    devconf = (struct iot_devconf_prov_data *) malloc(sizeof(struct iot_devconf_prov_data));
    assert_non_null(devconf);
    err = iot_api_onboarding_config_load(sample_onboarding_config, sizeof(sample_onboarding_config), devconf);
    assert_int_equal(err, IOT_ERROR_NONE);

    *state = devconf;

    return 0;
}

int TC_iot_easysetup_create_ssid_teardown(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data *devconf = (struct iot_devconf_prov_data *)*state;

    do_not_use_mock_iot_os_malloc_failure();

    iot_api_onboarding_config_mem_free(devconf);

    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}


void TC_iot_easysetup_create_ssid_null_parameters(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_devconf_prov_data devconf;

    // When: All parameters null
    err = iot_easysetup_create_ssid(NULL, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: devconf is null
    err = iot_easysetup_create_ssid(NULL, ssid, sizeof(ssid));
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: ssid is null
    err = iot_easysetup_create_ssid(&devconf, NULL, 0);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_easysetup_create_ssid_success(void **state)
{
    iot_error_t err;
    char ssid[33];
    struct iot_devconf_prov_data *devconf;

    // Given
    devconf = (struct iot_devconf_prov_data *)*state;
    // When: valid parameters
    err = iot_easysetup_create_ssid(devconf, ssid, sizeof(ssid));
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal(ssid, sample_ssid);
}

void TC_iot_easysetup_request_handler_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_easysetup_payload request;

    // Given
    request.step = IOT_EASYSETUP_STEP_DEVICEINFO;
    request.payload = NULL;
    request.err = IOT_ERROR_NONE;
    // When: ctx is null
    err = iot_easysetup_request_handler(NULL, request);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);
}