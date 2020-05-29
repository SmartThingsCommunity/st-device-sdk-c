/* ***************************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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

#include <string.h>

#include "iot_main.h"
#include "iot_debug.h"
#include "security/iot_security_common.h"

iot_error_t iot_security_ed25519_convert_pubkey(unsigned char *ed25519_key, unsigned char *curve25519_key)
{
	int ret;

	if (!ed25519_key || !curve25519_key) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = crypto_sign_ed25519_pk_to_curve25519(curve25519_key, ed25519_key);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_pk_to_curve25519 = %d", ret);
		return IOT_ERROR_SECURITY_KEY_CONVERT;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_security_ed25519_convert_seckey(unsigned char *ed25519_key, unsigned char *curve25519_key)
{
	int ret;

	if (!ed25519_key || !curve25519_key) {
		return IOT_ERROR_INVALID_ARGS;
	}

	ret = crypto_sign_ed25519_sk_to_curve25519(curve25519_key, ed25519_key);
	if (ret) {
		IOT_ERROR("crypto_sign_ed25519_sk_to_curve25519 = %d", ret);
		return IOT_ERROR_SECURITY_KEY_CONVERT;
	}

	return IOT_ERROR_NONE;
}