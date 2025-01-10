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
#include <iot_security_common.h>
#include <iot_security_util.h>

unsigned char sample_seckey_ed25519[] = {
	0xc9, 0x03, 0x2b, 0x14, 0xf9, 0x19, 0xd7, 0x02,
	0x3a, 0xd8, 0xad, 0x5c, 0x12, 0xe8, 0x52, 0x2f,
	0x6d, 0xf0, 0x05, 0x1f, 0xe7, 0x2e, 0xbe, 0xec,
	0xdd, 0x85, 0x19, 0x9f, 0xe5, 0xc0, 0xc1, 0xbf,
};

unsigned char sample_seckey_curve25519[] = {
	0xb8, 0x58, 0x17, 0x44, 0x8b, 0xbc, 0xeb, 0x00,
	0x62, 0x8d, 0xac, 0x78, 0x80, 0xc5, 0xeb, 0x42,
	0xcd, 0xa3, 0x48, 0x53, 0x90, 0x2f, 0x3d, 0x60,
	0x01, 0x93, 0x3e, 0x4f, 0xfb, 0xa7, 0xdf, 0x66,
};

extern iot_error_t _iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key);

void TC_iot_security_ed25519_convert_seckey_null_parameters(void **state)
{
	iot_error_t err;
	unsigned char *ed25519_key = sample_seckey_ed25519;
	unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

	// When: all null
	err = _iot_security_ed25519_convert_seckey(NULL, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// When: ed key null
	err = _iot_security_ed25519_convert_seckey(NULL, curve25519_key);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);

	// When: curve key null
	err = _iot_security_ed25519_convert_seckey(ed25519_key, NULL);
	// Then
	assert_int_equal(err, IOT_ERROR_INVALID_ARGS);
}

void TC_iot_security_ed25519_convert_seckey_success(void **state)
{
	iot_error_t err;
	unsigned char *ed25519_key;
	unsigned char curve25519_key[IOT_SECURITY_ED25519_LEN];

	// Given
	ed25519_key = sample_seckey_ed25519;
	// When
	err = _iot_security_ed25519_convert_seckey(ed25519_key, curve25519_key);
	// Then
	assert_int_equal(err, IOT_ERROR_NONE);
	assert_memory_equal(curve25519_key, sample_seckey_curve25519, sizeof(sample_seckey_curve25519));
}
