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
#include <iot_crypto.h>
#include <iot_wt.h>
#include "TC_MOCK_functions.h"

#define UNUSED(x) (void**)(x)

#define SAMPLE_SECKEY_B64  "ztqmQ24u86J9bpFLjaoMfwauUZwKLjUIGsnrDwwnDM8="
#define SAMPLE_PUBKEY_B64  "BKb7+m1Mo8OuMsodM91ohz/+rZKDc/otzUPSn4UkCUk="
static const char *sample_device_num = "STDKfJvW7a861805";

int TC_iot_wt_create_memleak_detect_setup(void **state)
{
	UNUSED(state);
	set_mock_detect_memory_leak(true);
	return 0;
}

int TC_iot_wt_create_memleak_detect_teardown(void **state)
{
	UNUSED(state);
	set_mock_detect_memory_leak(false);
	return 0;
}

void _fill_test_pkinfo(iot_crypto_pk_info_t *pk_info)
{
	iot_error_t err;
	unsigned char *pubkey;
	unsigned char *seckey;
	size_t key_len = IOT_CRYPTO_ED25519_LEN;
	size_t olen;

	pubkey = (unsigned char *)malloc(key_len);
	assert_non_null(pubkey);

	seckey = (unsigned char *)malloc(key_len);
	assert_non_null(seckey);

	pk_info->type = IOT_CRYPTO_PK_ED25519;

	err = iot_crypto_base64_decode(SAMPLE_PUBKEY_B64, strlen(SAMPLE_PUBKEY_B64), pubkey, key_len, &olen);
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, key_len);
	pk_info->pubkey = pubkey;
	pk_info->pubkey_len = olen;

	err = iot_crypto_base64_decode(SAMPLE_SECKEY_B64, strlen(SAMPLE_SECKEY_B64), seckey, key_len, &olen);
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_int_equal(olen, key_len);
	pk_info->seckey = seckey;
	pk_info->seckey_len = olen;
}

void TC_iot_wt_create_null_parameters(void **state)
{
	iot_error_t err;
	char *wt_data = NULL;
	char *dev_sn;
	struct iot_crypto_pk_info pk_info;
	UNUSED(state);

	// Given: All parameters are null
	// When
	err = iot_wt_create(NULL, NULL, NULL);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	memset(&pk_info, '\0', sizeof(iot_crypto_pk_info_t));
	_fill_test_pkinfo(&pk_info);
	// When: token, dev_sn is null
	err = iot_wt_create(NULL, NULL, &pk_info);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given
	dev_sn = (char *)sample_device_num;
	// When: token is null
	err = iot_wt_create(NULL, dev_sn, &pk_info);
	// Then: returns error
	assert_int_not_equal(err, IOT_ERROR_NONE);

	// Given: All parameters
	// When
	err = iot_wt_create(&wt_data, dev_sn, &pk_info);
	// Then: returns success
	assert_int_equal(err, IOT_ERROR_NONE);

	//local teardown
	if (pk_info.pubkey)
		free((void *)pk_info.pubkey);
	if (pk_info.seckey)
		free((void *)pk_info.seckey);
	if(wt_data)
		free(wt_data);
}
