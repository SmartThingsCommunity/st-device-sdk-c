/* ***************************************************************************
 *
 * Copyright (c) 2020-2021 Samsung Electronics All Rights Reserved.
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
#include <iot_nv_data.h>
#include <string.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

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

int TC_iot_api_memleak_detect_setup(void **state)
{
    UNUSED(state);
    set_mock_detect_memory_leak(true);
    return 0;
}

int TC_iot_api_memleak_detect_teardown(void **state)
{
    UNUSED(state);
    set_mock_detect_memory_leak(false);
    return 0;
}

void TC_iot_api_device_info_load_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // When: All parameters null
    err = iot_api_device_info_load(NULL, 10, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: device_info is null
    err = iot_api_device_info_load(NULL, 10, &info);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: info is null
    err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_api_device_info_load_success(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // When: valid input
    err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), &info);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("MyTestingFirmwareVersion", info.firmware_version);

    // local teardown
    iot_api_device_info_mem_free(&info);
}

void TC_iot_api_device_info_load_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    for (unsigned int i = 0; i < 2; i++) {
        // Given: i-th malloc failure
        memset(&info, '\0', sizeof(struct iot_device_info));
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid input
        err = iot_api_device_info_load(device_info_sample, sizeof(device_info_sample), &info);
        // Then: success
        assert_int_not_equal(err, IOT_ERROR_NONE);
        // local teardown
        iot_api_device_info_mem_free(&info);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

static char device_info_sample_without_firmware_version[] = {
        "{\n"
        "\t\"deviceInfo\": {\n"
        "\t\t\"privateKey\": \"privateKey_here\",\n"
        "\t\t\"publicKey\": \"publicKey_here\",\n"
        "\t\t\"serialNumber\": \"serialNumber_here\"\n"
        "\t}\n"
        "}"
};

void TC_iot_api_device_info_load_without_firmware_version(void **state)
{
    iot_error_t err;
    struct iot_device_info info;
    UNUSED(state);

    // Given
    memset(&info, '\0', sizeof(struct iot_device_info));
    // When: malformed json
    err = iot_api_device_info_load(device_info_sample_without_firmware_version, sizeof(device_info_sample_without_firmware_version), &info);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // local teardown
    iot_api_device_info_mem_free(&info);
}

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
        "    \"identityType\": \"ED25519_or_CERTIFICATE\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"DIP_ID\",\n"
        "      \"majorVersion\": 9999,\n"
        "      \"minorVersion\": 9999\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_load_null_parameters(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // When: All parameters null
    err = iot_api_onboarding_config_load(NULL, 0, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: NULL pointer at output parameter
    err = iot_api_onboarding_config_load(NULL, 0, &devconf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_api_onboarding_config_load_template_parameters(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: template is used as parameter
    err = iot_api_onboarding_config_load(onboarding_profile_template, sizeof(onboarding_profile_template), &devconf);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_example[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\",\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    },\n"
		"    \"ssidVersion\": 4,\n"
		"    \"productId\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\"\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_load_success(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    struct iot_uuid target_id = {
			.id = {0x52, 0xaa, 0x10, 0x78, 0x0f, 0xdd, 0x4d, 0xca,
				0x94, 0x3f, 0x87, 0xac, 0x0f, 0xe5, 0xee, 0x5f}
    };
    UNUSED(state);

    // When: valid parameters
    err = iot_api_onboarding_config_load(onboarding_profile_example, sizeof(onboarding_profile_example), &devconf);
    // Then: success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_string_equal("STDK", devconf.device_onboarding_id);
    assert_string_equal("fTST", devconf.mnid);
    assert_string_equal("001", devconf.setupid);
    assert_string_equal("STDK_BULB_0001", devconf.vid);
    assert_string_equal("Switch", devconf.device_type);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_BUTTON);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_JUSTWORKS);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_PIN);
    assert_true((unsigned)devconf.ownership_validation_type & (unsigned)IOT_OVF_TYPE_QR);
    assert_memory_equal(&target_id, &devconf.dip->dip_id, sizeof(struct iot_uuid));
	assert_int_equal(devconf.ssid_version, 4);

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

void TC_iot_api_onboarding_config_load_internal_failure(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    for (unsigned int i = 0; i < 7; i++) {
        // Given: i-th malloc failure
        memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
        do_not_use_mock_iot_os_malloc_failure();
        set_mock_iot_os_malloc_failure_with_index(i);
        // When: valid parameters
        err = iot_api_onboarding_config_load(onboarding_profile_example, sizeof(onboarding_profile_example), &devconf);
        // Then: failure
        assert_int_not_equal(err, IOT_ERROR_NONE);
        // Local teardown
        iot_api_onboarding_config_mem_free(&devconf);
    }

    // Teardown
    do_not_use_mock_iot_os_malloc_failure();
}

static char onboarding_profile_without_mnid[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"id\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\",\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_without_mnid(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: malformed parameters
    err = iot_api_onboarding_config_load(onboarding_profile_without_mnid, sizeof(onboarding_profile_without_mnid), &devconf);
    // Then: returns fail
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_invalid_ssid_version[] = {
		"{\n"
		"  \"onboardingConfig\": {\n"
		"    \"deviceOnboardingId\": \"STDK\",\n"
		"    \"mnId\": \"fTST\",\n"
		"    \"setupId\": \"001\",\n"
		"    \"vid\": \"STDK_BULB_0001\",\n"
		"    \"deviceTypeId\": \"Switch\",\n"
		"    \"ownershipValidationTypes\": [\n"
		"      \"JUSTWORKS\",\n"
		"      \"BUTTON\",\n"
		"      \"PIN\",\n"
		"      \"QR\"\n"
		"    ],\n"
		"    \"identityType\": \"ED25519\",\n"
		"    \"deviceIntegrationProfileKey\": {\n"
		"      \"id\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\",\n"
		"      \"majorVersion\": 0,\n"
		"      \"minorVersion\": 1\n"
		"    },"
  		"    \"ssidVersion\": 2,\n"
		"    \"productId\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\"\n"
		"  }\n"
		"}"
};

void TC_iot_api_onboarding_config_invalid_ssid_version(void **state)
{
	iot_error_t err;
	struct iot_devconf_prov_data devconf;
	UNUSED(state);

	// Given
	memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
	// When: malformed parameters
	err = iot_api_onboarding_config_load(onboarding_profile_invalid_ssid_version, sizeof(onboarding_profile_invalid_ssid_version), &devconf);
	// Then: returns fail
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Local teardown
	iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_invalid_onboarding_id_length_version_4[] = {
		"{\n"
		"  \"onboardingConfig\": {\n"
		"    \"deviceOnboardingId\": \"SmartThingsDev\",\n"
		"    \"mnId\": \"fTST\",\n"
		"    \"setupId\": \"001\",\n"
		"    \"vid\": \"STDK_BULB_0001\",\n"
		"    \"deviceTypeId\": \"Switch\",\n"
		"    \"ownershipValidationTypes\": [\n"
		"      \"JUSTWORKS\",\n"
		"      \"BUTTON\",\n"
		"      \"PIN\",\n"
		"      \"QR\"\n"
		"    ],\n"
		"    \"identityType\": \"ED25519\",\n"
		"    \"deviceIntegrationProfileKey\": {\n"
		"      \"id\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\",\n"
		"      \"majorVersion\": 0,\n"
		"      \"minorVersion\": 1\n"
		"    },"
		"    \"ssidVersion\": 4,\n"
		"    \"productId\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\"\n"
		"  }\n"
		"}"
};

void TC_iot_api_onboarding_config_invalid_onboarding_id_length_version_4(void **state)
{
	iot_error_t err;
	struct iot_devconf_prov_data devconf;
	UNUSED(state);

	// Given
	memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
	// When: malformed parameters
	err = iot_api_onboarding_config_load(onboarding_profile_invalid_onboarding_id_length_version_4,
									  sizeof(onboarding_profile_invalid_onboarding_id_length_version_4), &devconf);
	// Then: returns fail
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Local teardown
	iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_valid_onboarding_id_length_version_5[] = {
		"{\n"
		"  \"onboardingConfig\": {\n"
		"    \"deviceOnboardingId\": \"SmartThingsDev\",\n"
		"    \"mnId\": \"fTST\",\n"
		"    \"setupId\": \"001\",\n"
		"    \"vid\": \"STDK_BULB_0001\",\n"
		"    \"deviceTypeId\": \"Switch\",\n"
		"    \"ownershipValidationTypes\": [\n"
		"      \"JUSTWORKS\",\n"
		"      \"BUTTON\",\n"
		"      \"PIN\",\n"
		"      \"QR\"\n"
		"    ],\n"
		"    \"identityType\": \"ED25519\",\n"
		"    \"deviceIntegrationProfileKey\": {\n"
		"      \"id\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\",\n"
		"      \"majorVersion\": 0,\n"
		"      \"minorVersion\": 1\n"
		"    },"
		"    \"ssidVersion\": 5,\n"
		"    \"productId\": \"52aa1078-0fdd-4dca-943f-87ac0fe5ee5f\"\n"
		"  }\n"
		"}"
};

void TC_iot_api_onboarding_config_valid_onboarding_id_length_version_5(void **state)
{
	iot_error_t err;
	struct iot_devconf_prov_data devconf;
	UNUSED(state);

	// Given
	memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
	// When: malformed parameters
	err = iot_api_onboarding_config_load(onboarding_profile_valid_onboarding_id_length_version_5,
										 sizeof(onboarding_profile_valid_onboarding_id_length_version_5), &devconf);
	// Then: returns success
	assert_int_equal(err, IOT_ERROR_NONE);

	// Local teardown
	iot_api_onboarding_config_mem_free(&devconf);
}

static char onboarding_profile_without_dip_id[] = {
        "{\n"
        "  \"onboardingConfig\": {\n"
        "    \"deviceOnboardingId\": \"STDK\",\n"
        "    \"mnId\": \"fTST\",\n"
        "    \"setupId\": \"001\",\n"
        "    \"vid\": \"STDK_BULB_0001\",\n"
        "    \"deviceTypeId\": \"Switch\",\n"
        "    \"ownershipValidationTypes\": [\n"
        "      \"JUSTWORKS\",\n"
        "      \"BUTTON\",\n"
        "      \"PIN\",\n"
        "      \"QR\"\n"
        "    ],\n"
        "    \"identityType\": \"ED25519\",\n"
        "    \"deviceIntegrationProfileKey\": {\n"
        "      \"majorVersion\": 0,\n"
        "      \"minorVersion\": 1\n"
        "    }\n"
        "  }\n"
        "}"
};

void TC_iot_api_onboarding_config_without_dip_id(void **state)
{
    iot_error_t err;
    struct iot_devconf_prov_data devconf;
    UNUSED(state);

    // Given
    memset(&devconf, '\0', sizeof(struct iot_devconf_prov_data));
    // When: malformed parameters
    err = iot_api_onboarding_config_load(onboarding_profile_without_dip_id, sizeof(onboarding_profile_without_dip_id), &devconf);
    // Then: returns fail
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // Local teardown
    iot_api_onboarding_config_mem_free(&devconf);
}

void TC_iot_get_time_in_sec_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameters
    err = iot_get_time_in_sec(NULL, 0);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_sec_success(void **state)
{
    iot_error_t err;
    char time_buffer[32];
    UNUSED(state);

    // Given
    memset(time_buffer, '\0', sizeof(time_buffer));
    // When: valid parameters
    err = iot_get_time_in_sec(time_buffer, sizeof(time_buffer));
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(strlen(time_buffer) > 0);
    assert_int_not_equal(atol(time_buffer), 0);
}

void TC_iot_get_time_in_ms_null_parmaeters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameters
    err = iot_get_time_in_ms(NULL, 0);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_ms_success(void **state)
{
    iot_error_t err;
    char time_buffer[32];
    UNUSED(state);

    // Given
    memset(time_buffer, '\0', sizeof(time_buffer));
    // When: valid parameters
    err = iot_get_time_in_ms(time_buffer, sizeof(time_buffer));
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(strlen(time_buffer) > 0);
    assert_int_not_equal(atol(time_buffer), 0);
}

void TC_iot_get_time_in_sec_by_long_null_parameters(void **state)
{
    iot_error_t err;
    UNUSED(state);

    // When: null parameter
    err = iot_get_time_in_sec_by_long(NULL);
    // Then: return error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_get_time_in_sec_by_long_success(void **state)
{
    iot_error_t err;
    long seconds = 0;
    UNUSED(state);

    // When: valid parameter
    err = iot_get_time_in_sec_by_long(&seconds);
    // Then: return success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_true(seconds > 0);
}

void TC_iot_easysetup_request_success(void **state)
{
    iot_error_t err;
    int os_ret;
    struct iot_context *context;
    const char *test_payload = "{ message: \"\" }";
    struct iot_easysetup_payload received_payload;
    unsigned char easysetup_event = 0;
    UNUSED(state);

    // Given
    context = (struct iot_context*) calloc(1, sizeof(struct iot_context));
    assert_non_null(context);
    context->easysetup_req_queue = iot_os_queue_create(1, sizeof(struct iot_easysetup_payload));
    assert_non_null(context->easysetup_req_queue);
    context->iot_events = iot_os_eventgroup_create();
    assert_non_null(context->iot_events);

    // When
    err = iot_easysetup_request(context, IOT_EASYSETUP_STEP_DEVICEINFO, test_payload);

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    easysetup_event = iot_os_eventgroup_wait_bits(context->iot_events,
            IOT_EVENT_BIT_EASYSETUP_REQ, true, IOT_MAIN_TASK_DEFAULT_CYCLE);
    assert_int_not_equal(easysetup_event, 0);
    os_ret = iot_os_queue_receive(context->easysetup_req_queue, &received_payload, 0);
    assert_int_equal(os_ret, IOT_OS_TRUE);
    assert_string_equal(received_payload.payload, test_payload);

    // Teardown
    iot_os_queue_delete(context->easysetup_req_queue);
    iot_os_eventgroup_delete(context->iot_events);
    free(context);
}

static char misc_info_dip_example[] = {
    "{\"dip\":{\"id\":\"bb000ddd-92a0-42a3-86f0-b531f278af06\",\"maj\":0,\"min\":1}}"
};

static struct iot_dip_data dip_example = {
    .dip_id.id = {0xbb, 0x00, 0x0d, 0xdd, 0x92, 0xa0, 0x42, 0xa3,
                  0x86, 0xf0, 0xb5, 0x31, 0xf2, 0x78, 0xaf, 0x06},
    .dip_major_version = 0,
    .dip_minor_version = 1,
};

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

int TC_iot_misc_info_dip_setup(void **state)
{
    iot_error_t err;
    UNUSED(state);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
    err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
    err = iot_nv_init(NULL, 0);
#endif
    assert_int_equal(err, IOT_ERROR_NONE);

    err = iot_nv_set_misc_info(misc_info_dip_example);
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

int TC_iot_misc_info_dip_teardown(void **state) {
    iot_error_t err;
    UNUSED(state);

    err = iot_nv_deinit();
    assert_int_equal(err, IOT_ERROR_NONE);
    return 0;
}

void TC_iot_misc_info_load_invalid_parameters(void **state) {
    iot_error_t err;
    struct iot_dip_data load_dip;
    UNUSED(state);

    // When: out_data is null
    err = iot_misc_info_load(IOT_MISC_INFO_DIP, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: type is unsupported
    err = iot_misc_info_load(-1, (void *)&load_dip);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_misc_info_load_success(void **state) {
    iot_error_t err;
    struct iot_dip_data load_dip;
    UNUSED(state);

    // When: valid parameter
    err = iot_misc_info_load(IOT_MISC_INFO_DIP, (void *)&load_dip);
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(&dip_example.dip_id, &load_dip.dip_id, sizeof(struct iot_uuid));
    assert_int_equal(dip_example.dip_major_version, load_dip.dip_major_version);
    assert_int_equal(dip_example.dip_minor_version, load_dip.dip_minor_version);

    // Given: erase saved dip
    err = iot_nv_erase(IOT_NVD_MISC_INFO);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: valid parameter
    err = iot_misc_info_load(IOT_MISC_INFO_DIP, (void *)&load_dip);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_misc_info_store_invalid_parameters(void **state) {
    iot_error_t err;
    UNUSED(state);

    // When: out_data is null
    err = iot_misc_info_store(IOT_MISC_INFO_DIP, NULL);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);

    // When: All parameters null
    err = iot_misc_info_store(-1, (void *)&dip_example);
    // Then: returns error
    assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_misc_info_store_success(void **state) {
    iot_error_t err;
    char *new_dip_str;
    size_t str_len;
    UNUSED(state);

    // Given: erase saved dip
    err = iot_nv_erase(IOT_NVD_MISC_INFO);
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: store new dip
    err = iot_misc_info_store(IOT_MISC_INFO_DIP, (void *)&dip_example);
    // Then: returns success
    assert_int_equal(err, IOT_ERROR_NONE);

    // When: get raw data from NV
    err = iot_nv_get_misc_info(&new_dip_str, &str_len);
    // Then: There are same data
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_memory_equal(new_dip_str, misc_info_dip_example, sizeof(misc_info_dip_example));
}

void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_OFF(void **state) {
    iot_error_t err;
    struct iot_context *context;
    UNUSED(state);

    // Given
    context = (struct iot_context*) malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));
    context->scan_num = 3;
    context->scan_result = (iot_wifi_scan_result_t*) malloc ( context->scan_num * sizeof(iot_wifi_scan_result_t));
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_OFF);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = iot_wifi_ctrl_request(context, IOT_WIFI_MODE_OFF);

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->es_http_ready, 0);
    assert_int_equal(context->scan_num, 0);
    assert_null(context->scan_result);

    // Teardown
    free(context);
}

void TC_iot_wifi_ctrl_request_IOT_WIFI_MODE_SCAN(void **state) {
    iot_error_t err;
    struct iot_context *context;
    UNUSED(state);

    // Given
    context = (struct iot_context*) malloc(sizeof(struct iot_context));
    assert_non_null(context);
    memset(context, '\0', sizeof(struct iot_context));
    will_return(__wrap_iot_bsp_wifi_get_scan_result, 5);
    expect_value(__wrap_iot_bsp_wifi_set_mode, conf->mode, IOT_WIFI_MODE_SCAN);
    will_return(__wrap_iot_bsp_wifi_set_mode, IOT_ERROR_NONE);

    // When
    err = iot_wifi_ctrl_request(context, IOT_WIFI_MODE_SCAN);

    // Then
    assert_int_equal(err, IOT_ERROR_NONE);
    assert_int_equal(context->scan_num, 5);
    assert_non_null(context->scan_result);

    // Teardown
    iot_os_free(context->scan_result);
    free(context);
}