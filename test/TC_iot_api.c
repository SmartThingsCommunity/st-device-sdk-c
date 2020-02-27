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
#include <iot_error.h>
#include <iot_internal.h>
#include <iot_os_util.h>
#include <iot_easysetup.h>

static char device_info_sample[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"firmwareVersion\": \"MyTestingFirmwareVersion\",\n"
        "\t\t\"privateKey\": \"privateKey_here\",\n"
        "\t\t\"publicKey\": \"publicKey_here\",\n"
        "\t\t\"serialNumber\": \"serialNumber_here\"\n"
        "\t}\n"
        "}"
};

static char onboarding_profile_template[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"NAME\",\n"
        "    \"mnId\": \"MNID\",\n"
        "    \"setupId\": \"999\",\n"
        "    \"vid\": \"VID\",\n"
        "    \"deviceTypeId\": \"TYPE\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519_or_CERTIFICATE\"\n"
        "  }\n"
        "}"
};

static char onboarding_profile_example[] = {
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
void TC_iot_api_device_info_load(void **state)
{
    iot_error_t err;
    struct iot_device_info info;

    // When: null parameters
    err = iot_api_device_info_load(NULL, 10, NULL);
    // Then
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: valid input
    err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), &info);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("MyTestingFirmwareVersion", info.firmware_version);
}

void TC_iot_api_onboarding_config_load(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), NULL);
    // Then: error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(NULL, 0, &devconf);
    // Then: error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: template
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), &devconf);
    // Then: error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: example
    err = iot_api_onboarding_config_load(onboarding_profile_example, sizeof(onboarding_profile_example), &devconf);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("STDK", devconf.device_onboarding_id);
    assert_string_equal("fTST", devconf.mnid);
    assert_string_equal("001", devconf.setupid);
    assert_string_equal("STDK_BULB_0001", devconf.vid);
    assert_string_equal("Switch", devconf.device_type);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_BUTTON);
    assert_false((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_JUSTWORKS);
    assert_false((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_PIN);
    assert_false((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_QR);

}