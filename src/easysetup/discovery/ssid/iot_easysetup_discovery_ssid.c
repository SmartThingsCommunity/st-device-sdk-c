/* ***************************************************************************
 *
 * Copyright (c) 2021 Samsung Electronics All Rights Reserved.
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
#include <iot_nv_data.h>
#include <iot_easysetup.h>
#include <iot_debug.h>
#include <iot_error.h>
#include <security/iot_security_helper.h>

#define HASH_SIZE (4)
#if defined(CONFIG_STDK_IOT_CORE_EASYSETUP_X509)
#define SETUP_TYPE_HYBRID_SERIAL_NUMBER	(7)
#else
#define SETUP_TYPE_HYBRID_SERIAL_NUMBER	(6)
#endif

iot_error_t iot_easysetup_create_ssid(struct iot_devconf_prov_data *devconf, char *ssid, size_t ssid_len)
{
	char *serial = NULL;
	unsigned char hash_buffer[IOT_SECURITY_SHA256_LEN] = { 0, };
	unsigned char base64url_buffer[IOT_SECURITY_B64_ENCODE_LEN(IOT_SECURITY_SHA256_LEN)] = { 0, };
	size_t base64_written = 0;
	char ssid_build[33] = { 0, };
	unsigned char last_sn[HASH_SIZE + 1] = { 0,};
	unsigned char hashed_sn[HASH_SIZE + 1] = { 0,};
	size_t length;
	int i, setup_type;
	iot_error_t err = IOT_ERROR_NONE;

	IOT_WARN_CHECK((devconf == NULL || ssid == NULL || ssid_len == 0), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	err = iot_nv_get_serial_number(&serial, &length);
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed to get serial number (%d)", err);
		goto out;
	}
	err = iot_security_sha256((unsigned char*)serial, length, hash_buffer, sizeof(hash_buffer));
	if (err != IOT_ERROR_NONE) {
		IOT_ERROR("Failed sha256 (%d)", err);
		goto out;
	}
	err = iot_security_base64_encode_urlsafe(hash_buffer, sizeof(hash_buffer),
											 base64url_buffer, sizeof(base64url_buffer), &base64_written);
	if (err != IOT_ERROR_NONE)
		goto out;

	if (base64_written >= HASH_SIZE) {
		if (devconf->hashed_sn) {
			iot_os_free(devconf->hashed_sn);
			devconf->hashed_sn = NULL;
		}

		devconf->hashed_sn = iot_os_malloc(base64_written + 1);
		if (!devconf->hashed_sn) {
			err = IOT_ERROR_MEM_ALLOC;
			goto out;
		}
		memset(devconf->hashed_sn, '\0', base64_written + 1);
		memcpy(devconf->hashed_sn, base64url_buffer, base64_written);
		memcpy(hashed_sn, base64url_buffer, HASH_SIZE);
	} else {
		err = IOT_ERROR_SECURITY_BASE64_URL_ENCODE;
		goto out;
	}
	hashed_sn[HASH_SIZE] = '\0';

	for (i = 0; i < HASH_SIZE; i++) {
		if (length < (HASH_SIZE - i))
			last_sn[i] = 0;
		else
			last_sn[i] = serial[length - (HASH_SIZE - i)];
	}
	last_sn[HASH_SIZE] = '\0';
	IOT_INFO(">> %s[%c%c%c%c] <<", devconf->device_onboarding_id,
			 last_sn[0], last_sn[1],
			 last_sn[2], last_sn[3]);

	setup_type = SETUP_TYPE_HYBRID_SERIAL_NUMBER;

	if (devconf->ssid_version == 4) {
		snprintf(ssid_build, sizeof(ssid_build), "%s_E4%4s%3s%1d%4s%4s",
				 devconf->device_onboarding_id, devconf->mnid, devconf->setupid, setup_type, hashed_sn, last_sn);
	} else if (devconf->ssid_version == 5) {
		snprintf(ssid_build, sizeof(ssid_build), "%s_E5%4s%3s%4s%4s",
				 devconf->device_onboarding_id, devconf->mnid, devconf->setupid, hashed_sn, last_sn);
	} else {
		err = IOT_ERROR_INVALID_ARGS;
		goto out;
	}

	memcpy(ssid, ssid_build, ssid_len < strlen(ssid_build) ? ssid_len : strlen(ssid_build));
out:
	if (err && devconf->hashed_sn) {
		iot_os_free(devconf->hashed_sn);
		devconf->hashed_sn = NULL;
	}
	if (serial) {
		iot_os_free(serial);
	}
	return err;
}