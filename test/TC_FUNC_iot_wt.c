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
#include <string.h>
#include <iot_error.h>
#include <iot_wt.h>
#include <iot_nv_data.h>
#include <security/iot_security_helper.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

static char sample_device_info[] = {
	"{\n"
	"\t\"deviceInfo\": {\n"
	"\t\t\"firmwareVersion\": \"testFirmwareVersion\",\n"
	"\t\t\"privateKey\": \"y04i7Pme6rJTkLBPngQoZfEI5KEAyE70A9xOhoX8uTI=\",\n"
	"\t\t\"publicKey\": \"Sh4cBHRnPuEFyinaVuEd+mE5IQTkwPHmbOrgD3fwPsw=\",\n"
	"\t\t\"serialNumber\": \"STDKtestc77078cc\"\n"
	"\t}\n"
	"}"
};

static const char *sample_mnid = "test";
static const char *sample_sn = "STDKtestc77078cc";

int TC_iot_wt_create_memleak_detect_setup(void **state)
{
	iot_error_t err;
	UNUSED(state);

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	err = iot_nv_init((unsigned char *)sample_device_info, strlen(sample_device_info));
#else
	err = iot_nv_init(NULL, 0);
#endif
	assert_int_equal(err, IOT_ERROR_NONE);

	set_mock_detect_memory_leak(true);
	return 0;
}

int TC_iot_wt_create_memleak_detect_teardown(void **state)
{
	iot_error_t err;
	UNUSED(state);

	set_mock_detect_memory_leak(false);
	err = iot_nv_deinit();
	assert_int_equal(err, IOT_ERROR_NONE);
	return 0;
}

void TC_iot_wt_create_null_parameters(void **state)
{
	iot_error_t err;
	iot_wt_params_t wt_params;
	iot_security_buffer_t token_buf = { 0 };
	UNUSED(state);

	// When: All parameters are null
	err = iot_wt_create(NULL, NULL);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// When: token is null
	err = iot_wt_create(&wt_params, NULL);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: sn and mnid are null
	memset(&wt_params, 0, sizeof(wt_params));
	// When
	err = iot_wt_create(&wt_params, &token_buf);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: sn is null
	memset(&wt_params, 0, sizeof(wt_params));
	wt_params.mnid = (char *)sample_mnid;
	wt_params.mnid_len = strlen(sample_mnid);
	// When
	err = iot_wt_create(&wt_params, &token_buf);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: mnid is null
	memset(&wt_params, 0, sizeof(wt_params));
	wt_params.sn = (char *)sample_sn;
	wt_params.sn_len = strlen(sample_sn);
	// When
	err = iot_wt_create(&wt_params, &token_buf);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);
}

void TC_iot_wt_create_success(void **state)
{
	iot_error_t err;
	iot_wt_params_t wt_params;
	iot_security_buffer_t token_buf = { 0 };
	UNUSED(state);

	// Given
	wt_params.sn = (char *)sample_sn;
	wt_params.sn_len = strlen(sample_sn);
	wt_params.mnid = (char *)sample_mnid;
	wt_params.mnid_len = strlen(sample_mnid);
	// When
	err = iot_wt_create(&wt_params, &token_buf);
	// Then: returns success
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_non_null(token_buf.p);

	// Local teardown
	iot_os_free(token_buf.p);
}
