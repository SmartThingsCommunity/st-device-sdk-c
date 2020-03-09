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
#include <sys/time.h>

#include "iot_main.h"
#include "iot_crypto.h"
#include "iot_uuid.h"
#include "iot_bsp_random.h"
#include "iot_debug.h"

iot_error_t iot_random_uuid_from_mac(struct iot_uuid *uuid)
{
	iot_error_t err;
	struct timeval tv;
	struct iot_mac mac;
	unsigned char hash[IOT_CRYPTO_SHA256_LEN];
	unsigned char *buf;
	size_t buf_len;
	int ret;

	if (!uuid) {
		IOT_ERROR("UUID ptr is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	err = iot_bsp_wifi_get_mac(&mac);
	if(err) {
		IOT_ERROR("iot_bsp_wifi_get_mac failed, ret = %d", err);
		return err;
	}

	ret = gettimeofday(&tv, NULL);
	if (ret) {
		IOT_ERROR("gettimeofday failed, ret = %d", ret);
		return IOT_ERROR_UUID_FAIL;
	}

	buf_len = sizeof(mac) + sizeof(tv);

	buf = (unsigned char *)iot_os_malloc(buf_len);
	if (!buf) {
		IOT_ERROR("malloc failed for buf");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(buf, 0, buf_len);
	memcpy(buf, &mac, sizeof(mac));
	memcpy(buf + sizeof(mac), &tv, sizeof(tv));

	/*
	 * uuid = first16byte(sha256(mac + usec))
	 */
	err = iot_crypto_sha256(buf, buf_len, hash);
	if (err) {
		IOT_ERROR("iot_crypto_sha256 failed, ret = %d", err);
		free((void *)buf);
		return err;
	}

	memcpy((void *)uuid, hash, sizeof(struct iot_uuid));

	free((void *)buf);

	return IOT_ERROR_NONE;
}

iot_error_t iot_uuid_from_mac(struct iot_uuid *uuid)
{
	iot_error_t err;
	struct iot_mac mac;
	unsigned char hash[IOT_CRYPTO_SHA256_LEN];
	unsigned char *buf;
	size_t buf_len;

	if (!uuid) {
		IOT_ERROR("UUID ptr is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	err = iot_bsp_wifi_get_mac(&mac);
	if(err) {
		IOT_ERROR("iot_bsp_wifi_get_mac failed, ret = %d", err);
		return err;
	}

	buf_len = sizeof(mac);

	buf = (unsigned char *)iot_os_malloc(buf_len);
	if (!buf) {
		IOT_ERROR("malloc failed for buf");
		return IOT_ERROR_MEM_ALLOC;
	}

	memset(buf, 0, buf_len);
	memcpy(buf, &mac, buf_len);

	/*
	 * uuid = first16byte(sha256(mac))
	 */
	err = iot_crypto_sha256(buf, buf_len, hash);
	if (err) {
		IOT_ERROR("iot_crypto_sha256 failed, err = %d", err);
		free((void *)buf);
		return err;
	}

	memcpy((void *)uuid, hash, sizeof(struct iot_uuid));

	free((void *)buf);

	return IOT_ERROR_NONE;
}
