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
#include <iot_error.h>
#include <iot_bsp_ble.h>

iot_error_t iot_easysetup_create_ble_advertise_packet(struct iot_context *ctx)
{
	char *serial = NULL;
	size_t length;
	size_t base64_written = 0;
	int i;
	iot_error_t err = IOT_ERROR_NONE;
	unsigned char hash_buffer[IOT_SECURITY_SHA256_LEN] = { 0, };
	unsigned char base64url_buffer[IOT_SECURITY_B64_ENCODE_LEN(IOT_SECURITY_SHA256_LEN)] = { 0, };

	IOT_WARN_CHECK((ctx == NULL), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

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
	if (err != IOT_ERROR_NONE) {
		err = IOT_ERROR_SECURITY_BASE64_URL_ENCODE;
		goto out;
	}

	if (ctx->devconf.hashed_sn) {
		iot_os_free(ctx->devconf.hashed_sn);
		ctx->devconf.hashed_sn = NULL;
	}

	ctx->devconf.hashed_sn = iot_os_malloc(base64_written + 1);
	if (!ctx->devconf.hashed_sn) {
		err = IOT_ERROR_MEM_ALLOC;
		goto out;
	}
	memset(ctx->devconf.hashed_sn, '\0', base64_written + 1);
	memcpy(ctx->devconf.hashed_sn, base64url_buffer, base64_written);

	iot_create_advertise_packet(ctx->devconf.mnid, ctx->devconf.setupid, (char *)serial);
	iot_create_scan_response_packet(ctx->devconf.device_onboarding_id, (char *)serial);
out:
	if (err && ctx->devconf.hashed_sn) {
		iot_os_free(ctx->devconf.hashed_sn);
		ctx->devconf.hashed_sn = NULL;
	}
	if (serial) {
		iot_os_free(serial);
	}
	return err;
}
