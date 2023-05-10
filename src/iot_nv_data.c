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
#include <stdlib.h>

#include "iot_nv_data.h"
#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"
#include "iot_util.h"
#include "certs/root_ca.h"
#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
#include "iot_internal.h"
#endif
#include "security/iot_security_helper.h"
#include "security/iot_security_manager.h"
#include "security/iot_security_storage.h"

#define IOT_NVD_MAX_DATA_LEN (2048)
#define IOT_NVD_MAX_BSSID_LEN (6)
#define IOT_NVD_MAX_UID_LEN (128)
#define IOT_NVD_MAX_SN_LEN (30)

typedef enum iot_nv_io_mode {
	IOT_NV_MODE_READ = 1,
	IOT_NV_MODE_WRITE,
	IOT_NV_MODE_REMOVE,
} iot_nv_io_mode_t;

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
static unsigned char *device_nv_info;
static size_t device_nv_info_len;
static const char name_privateKey[] = "privateKey";
static const char name_publicKey[] = "publicKey";
static const char name_rootCaCert[] = "rootCaCert";
static const char name_subCaCert[] = "subCaCert";
static const char name_deviceCert[] = "deviceCert";
static const char name_serialNumber[] = "serialNumber";
#endif

STATIC_FUNCTION
iot_security_context_t *_iot_nv_io_storage_init(void)
{
	iot_error_t err;
	iot_security_context_t *security_context;

	security_context = iot_security_init();
	if (!security_context) {
		IOT_ERROR("failed to init security");
		return NULL;
	}

	err = iot_security_storage_init(security_context);
	if (err) {
		IOT_ERROR("iot_security_storage_init = %d", err);
		iot_security_deinit(security_context);
		return NULL;
	}

	return security_context;
}

STATIC_FUNCTION
iot_error_t _iot_nv_io_storage_deinit(iot_security_context_t *security_context)
{
	iot_error_t err;

	err = iot_security_storage_deinit(security_context);
	if (err) {
		return err;
	}

	err = iot_security_deinit(security_context);
	if (err) {
		return err;
	}

	return IOT_ERROR_NONE;
}

STATIC_FUNCTION
iot_error_t _iot_nv_io_storage(const iot_nvd_t nv_id, iot_nv_io_mode_t mode, char *data, size_t data_len, size_t *read_len)
{
	iot_error_t err = IOT_ERROR_NONE;
	iot_security_context_t *security_context;
	iot_security_buffer_t data_buf = {0};

	IOT_DEBUG("id = %d, mode = %d", nv_id, mode);

	if ((nv_id < 0 || nv_id >= IOT_NVD_MAX)) {
		IOT_ERROR("nv type is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	if ((mode != IOT_NV_MODE_REMOVE) && (!data || (data_len == 0))) {
		IOT_ERROR("data input is invalid");
		return IOT_ERROR_INVALID_ARGS;
	}

	security_context = _iot_nv_io_storage_init();
	IOT_ERROR_CHECK(security_context == NULL, IOT_ERROR_NV_DATA_ERROR, "failed to init storage");

	switch (mode) {
	case IOT_NV_MODE_READ:
		err = iot_security_storage_read(security_context, nv_id, &data_buf);
		if (err != IOT_ERROR_NONE) {
			if (err == IOT_ERROR_SECURITY_FS_NOT_FOUND) {
				IOT_DEBUG("nv '%d' does not exist", nv_id);
				err = IOT_ERROR_NV_DATA_NOT_EXIST;
			} else {
				IOT_ERROR("iot_security_storage_read = %d", err);
				err = IOT_ERROR_NV_DATA_ERROR;
			}
			break;
		}

		if (data_len < data_buf.len) {
			IOT_ERROR("output buffer is not enough (%d < %d)", data_len, data_buf.len);
			err = IOT_ERROR_SECURITY_FS_BUFFER;
			iot_os_free(data_buf.p);
			break;
		}

		memcpy(data, data_buf.p, data_buf.len);
		/* make null terminated string */
		if (data_buf.len < data_len) {
			data[data_buf.len] = '\0';
		}

		if (read_len != NULL) {
			*read_len = data_buf.len;
		}

		iot_os_free(data_buf.p);
		break;
	case IOT_NV_MODE_WRITE:
		data_buf.p = (unsigned char *)data;
		data_buf.len = data_len;

		err = iot_security_storage_write(security_context, nv_id, &data_buf);
		if (err != IOT_ERROR_NONE) {
			IOT_ERROR("iot_security_storage_write = %d", err);
			err = IOT_ERROR_NV_DATA_ERROR;
		}
		break;
	case IOT_NV_MODE_REMOVE:
                err = iot_security_storage_remove(security_context, nv_id);
		if (err != IOT_ERROR_NONE) {
			if (err == IOT_ERROR_SECURITY_FS_NOT_FOUND) {
				IOT_DEBUG("nv '%d' does not exist", nv_id);
				err = IOT_ERROR_NV_DATA_NOT_EXIST;
			} else {
				IOT_ERROR("iot_security_storage_remove = %d", err);
				err = IOT_ERROR_NV_DATA_ERROR;
			}
		}
		break;
	}

	(void)_iot_nv_io_storage_deinit(security_context);

	return err;
}

iot_error_t _iot_nv_read_data(const iot_nvd_t nv_type, char *data, size_t data_len, size_t *read_len)
{
	return _iot_nv_io_storage(nv_type, IOT_NV_MODE_READ, data, data_len, read_len);
}

iot_error_t _iot_nv_write_data(const iot_nvd_t nv_type, const char *data, size_t data_len)
{
	return _iot_nv_io_storage(nv_type, IOT_NV_MODE_WRITE, (char *)data, data_len, NULL);
}

iot_error_t _iot_nv_remove_data(const iot_nvd_t nv_type)
{
	return _iot_nv_io_storage(nv_type, IOT_NV_MODE_REMOVE, NULL, 0, NULL);
}

iot_error_t iot_nv_init(unsigned char *device_info, size_t device_info_len)
{
	HIT();
	iot_error_t ret = iot_bsp_fs_init();
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_INIT_FAIL, "NV init fail");

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	unsigned char* data = NULL;

	data = iot_os_malloc(device_info_len + 1);
	memcpy(data, device_info, device_info_len);
	data[device_info_len] = '\0';

	device_nv_info = data;
	device_nv_info_len = device_info_len;
#endif
	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_deinit()
{
	HIT();
	iot_error_t ret = iot_bsp_fs_deinit();
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_DEINIT_FAIL, "NV deinit fail");

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	if (device_nv_info) {
		iot_os_free(device_nv_info);
	}
	device_nv_info = NULL;
	device_nv_info_len = 0;
#endif
	return IOT_ERROR_NONE;
}

bool iot_nv_prov_data_exist(void)
{
	iot_error_t ret;
	char nv_status[5];

	memset(nv_status, 0, sizeof(nv_status));

	/* CHECK IOT_NVD_WIFI_PROV_STATUS */
	ret = _iot_nv_read_data(IOT_NVD_WIFI_PROV_STATUS, nv_status, sizeof(nv_status) - 1, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Wifi Prov Status : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_WIFI_PROV_STATUS, __LINE__);
		return false;
	}

	if (strncmp(nv_status, "DONE", 4)) {
		IOT_DEBUG("No wifi provisioning data");
		return false;
	}

	memset(nv_status, 0, sizeof(nv_status));

	/* CHECK IOT_NVD_CLOUD_PROV_STATUS */
	ret = _iot_nv_read_data(IOT_NVD_CLOUD_PROV_STATUS, nv_status, sizeof(nv_status) - 1, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Cloud Prov Status : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_CLOUD_PROV_STATUS, __LINE__);
		return false;
	}

	if (strncmp(nv_status, "DONE", 4)) {
		IOT_DEBUG("No cloud provisioning data");
		return false;
	}

	return true;
}

iot_error_t iot_nv_get_prov_data(struct iot_device_prov_data* prov_data)
{
	HIT();
	IOT_WARN_CHECK(prov_data == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	iot_error_t ret;

	ret = iot_nv_get_wifi_prov_data(&prov_data->wifi);
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_NV_DATA_ERROR, "get wifi prov fail");

	ret = iot_nv_get_cloud_prov_data(&prov_data->cloud);
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_NV_DATA_ERROR, "get cloud prov fail");

	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_set_prov_data(struct iot_device_prov_data* prov_data)
{
	HIT();
	IOT_WARN_CHECK(prov_data == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	iot_error_t ret;

	ret = iot_nv_set_wifi_prov_data(&prov_data->wifi);
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_NV_DATA_ERROR, "set wifi prov fail");

	ret = iot_nv_set_cloud_prov_data(&prov_data->cloud);
	IOT_DEBUG_CHECK(ret != IOT_ERROR_NONE, IOT_ERROR_NV_DATA_ERROR, "set cloud prov fail");

	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_erase_prov_data()
{
	HIT();

	/*
	 * Todo :
	 * IOT_NVD_WIFI_PROV_STATUS
	 * IOT_NVD_CLOUD_PROV_STATUS
	 */
	iot_error_t ret;
	const char* status = "NONE";

	ret = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, status, strlen(status));
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Wifi Prov Status : write fail");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_WIFI_PROV_STATUS, __LINE__);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	ret = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, status, strlen(status));
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Cloud Prov Status : write fail");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_CLOUD_PROV_STATUS, __LINE__);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_get_wifi_prov_data(struct iot_wifi_prov_data* wifi_prov)
{
	HIT();
	IOT_WARN_CHECK(wifi_prov == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_WIFI_PROV_STATUS
	 * IOT_NVD_AP_SSID
	 * IOT_NVD_AP_PASS
	 * IOT_NVD_AP_BSSID
	 * IOT_NVD_AP_AUTH_TYPE
	 */
	iot_error_t ret;
	const int DATA_SIZE = IOT_WIFI_PROV_PASSWORD_STR_LEN + 1;
	unsigned int size;
	char* data = NULL;

	data = malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	/* CHECK IOT_NVD_WIFI_PROV_STATUS */
	ret = _iot_nv_read_data(IOT_NVD_WIFI_PROV_STATUS, data, DATA_SIZE, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Wifi Prov Status : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_WIFI_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	if (strncmp(data, "DONE", 4)) {
		IOT_DEBUG("No wifi provisioning data");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_AP_SSID */
	ret = _iot_nv_read_data(IOT_NVD_AP_SSID, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		size = strlen(data);
		if (size < IOT_WIFI_PROV_SSID_STR_LEN) {
			snprintf(wifi_prov->ssid, IOT_WIFI_PROV_SSID_STR_LEN, "%s", data);
		} else {
			memcpy(wifi_prov->ssid, data, IOT_WIFI_PROV_SSID_STR_LEN);
			wifi_prov->ssid[IOT_WIFI_PROV_SSID_STR_LEN] = '\0';
		}
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		wifi_prov->ssid[0] = '\0';
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("AP SSID : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_AP_SSID, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_AP_PASS */
	ret = _iot_nv_read_data(IOT_NVD_AP_PASS, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		size = strlen(data);
		if (size < IOT_WIFI_PROV_PASSWORD_STR_LEN) {
			snprintf(wifi_prov->password, IOT_WIFI_PROV_PASSWORD_STR_LEN, "%s", data);
		} else {
			memcpy(wifi_prov->password, data, IOT_WIFI_PROV_PASSWORD_STR_LEN);
			wifi_prov->password[IOT_WIFI_PROV_PASSWORD_STR_LEN] = '\0';
		}
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		wifi_prov->password[0] = '\0';
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("AP PW : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_AP_PASS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_AP_BSSID */
	size_t read_len = 0;
	ret = _iot_nv_read_data(IOT_NVD_AP_BSSID, data, DATA_SIZE, &read_len);
	if (ret == IOT_ERROR_NONE) {
		if (read_len >= IOT_WIFI_PROV_MAC_STR_LEN) {
			/* bssid : new style, 17byte string case */
			memcpy(wifi_prov->mac_str, data, IOT_WIFI_PROV_MAC_STR_LEN);
			wifi_prov->mac_str[IOT_WIFI_PROV_MAC_STR_LEN] = '\0';
			ret = iot_util_convert_str_mac(wifi_prov->mac_str, &wifi_prov->bssid);
			if (ret != IOT_ERROR_NONE) {
				IOT_INFO("Saved AP BSSID is invalid string(%d):%s",
					ret, wifi_prov->mac_str);
				memset(wifi_prov->mac_str, '\0', sizeof(wifi_prov->mac_str));
				memset(wifi_prov->bssid.addr, 0, sizeof(wifi_prov->bssid.addr));
				ret = IOT_ERROR_NONE;
			}
		} else if (read_len >= IOT_NVD_MAX_BSSID_LEN) {
			/* bssid : old style, 6byte chunk data case */
			memcpy(wifi_prov->bssid.addr, data, IOT_NVD_MAX_BSSID_LEN);
			ret = iot_util_convert_mac_str(&wifi_prov->bssid, wifi_prov->mac_str,
					sizeof(wifi_prov->mac_str));
			if (ret != IOT_ERROR_NONE) {
				IOT_INFO("Saved AP BSSID is invalid chunk(%d)", ret);
				memset(wifi_prov->mac_str, '\0', sizeof(wifi_prov->mac_str));
				memset(wifi_prov->bssid.addr, 0, sizeof(wifi_prov->bssid.addr));
				ret = IOT_ERROR_NONE;
			}
		} else {
			IOT_INFO("Saved AP BSSID is invalid length:%u", (unsigned int)read_len);
			memset(wifi_prov->mac_str, '\0', sizeof(wifi_prov->mac_str));
			memset(wifi_prov->bssid.addr, 0, sizeof(wifi_prov->bssid.addr));
		}
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		memset(wifi_prov->mac_str, '\0', sizeof(wifi_prov->mac_str));
		memset(wifi_prov->bssid.addr, 0, sizeof(wifi_prov->bssid.addr));
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("AP BSSID : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_AP_BSSID, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_AP_AUTH_TYPE */
	ret = _iot_nv_read_data(IOT_NVD_AP_AUTH_TYPE, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		wifi_prov->security_type = atoi(data);
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		wifi_prov->security_type = -1;
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("Auth Type : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_AP_AUTH_TYPE, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

exit:
	free(data);

	return ret;
}

iot_error_t iot_nv_set_wifi_prov_data(struct iot_wifi_prov_data* wifi_prov)
{
	HIT();
	IOT_WARN_CHECK(wifi_prov == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_WIFI_PROV_STATUS
	 * IOT_NVD_AP_SSID
	 * IOT_NVD_AP_PASS
	 * IOT_NVD_AP_BSSID
	 * IOT_NVD_AP_AUTH_TYPE
	 */
	iot_error_t ret;
	const int DATA_SIZE = IOT_WIFI_PROV_PASSWORD_STR_LEN + 1;
	unsigned int size;
	int state;
	char* data = NULL;

	data = malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	/* IOT_NVD_WIFI_PROV_STATUS - NONE */
	size = 4;
	memcpy(data, "NONE", size);
	data[size] = '\0';

	ret = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, data, size);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Wifi Prov Status : write failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_WIFI_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_AP_SSID */
	if (wifi_prov->ssid[0] == '\0') {
		iot_nv_erase(IOT_NVD_AP_SSID);
	} else {
		size = IOT_WIFI_PROV_SSID_STR_LEN;
		memcpy(data, wifi_prov->ssid, size);
		data[size] = '\0';

		ret = _iot_nv_write_data(IOT_NVD_AP_SSID, data, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("AP SSID : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_AP_SSID, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_AP_PASS */
	if (wifi_prov->password[0] == '\0') {
		iot_nv_erase(IOT_NVD_AP_PASS);
	} else {
		size = IOT_WIFI_PROV_PASSWORD_STR_LEN;
		memcpy(data, wifi_prov->password, size);
		data[size] = '\0';

		ret = _iot_nv_write_data(IOT_NVD_AP_PASS, data, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("AP PASS : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_AP_PASS, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_AP_BSSID */
	if (wifi_prov->mac_str[0] == '\0') {
		iot_nv_erase(IOT_NVD_AP_BSSID);
	} else {
		size = IOT_WIFI_PROV_MAC_STR_LEN;
		memcpy(data, wifi_prov->mac_str, size);
		data[size] = '\0';

		ret = _iot_nv_write_data(IOT_NVD_AP_BSSID, data, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("AP BSSID : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_AP_BSSID, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_AP_AUTH_TYPE */
	if (wifi_prov->security_type < IOT_WIFI_AUTH_OPEN || wifi_prov->security_type > IOT_WIFI_AUTH_MAX) {
		iot_nv_erase(IOT_NVD_AP_AUTH_TYPE);
	} else {
		state = snprintf(data, DATA_SIZE, "%d", wifi_prov->security_type);
		if (state <= 0) {
			IOT_DEBUG("Auth Type : data load failed from prov structure");
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}

		size = state;
		data[size] = '\0';

		ret = _iot_nv_write_data(IOT_NVD_AP_AUTH_TYPE, data, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("Auth Type : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_AP_AUTH_TYPE, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_WIFI_PROV_STATUS - DONE */
	size = 4;
	memcpy(data, "DONE", size);
	data[size] = '\0';

	ret = _iot_nv_write_data(IOT_NVD_WIFI_PROV_STATUS, data, size);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Wifi Prov Status : write failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_WIFI_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

exit:
	free(data);

	return ret;
}

iot_error_t iot_nv_get_cloud_prov_data(struct iot_cloud_prov_data* cloud_prov)
{
	HIT();
	IOT_WARN_CHECK(cloud_prov == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_CLOUD_PROV_STATUS
	 * IOT_NVD_SERVER_URL
	 * IOT_NVD_SERVER_PORT
	 * IOT_NVD_LOCATION_ID
	 * IOT_NVD_ROOM_ID
	 * IOT_NVD_LABEL
	 */
	iot_error_t ret;
	const int DATA_SIZE = (IOT_NVD_MAX_DATA_LEN / 2) + 1;
	unsigned int size;
	char* data = NULL;
	char* new_buff = NULL;

	data = iot_os_malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	/* CHECK IOT_NVD_CLOUD_PROV_STATUS */
	ret = _iot_nv_read_data(IOT_NVD_CLOUD_PROV_STATUS, data, DATA_SIZE, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Cloud Prov Status : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_CLOUD_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	if (strncmp(data, "DONE", 4)) {
		IOT_DEBUG("No cloud provisioning data");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_SERVER_URL */
	ret = _iot_nv_read_data(IOT_NVD_SERVER_URL, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		size = strlen(data);
		new_buff = (char *)iot_os_malloc(size + 1);
		if (new_buff == NULL) {
			IOT_WARN("failed to malloc for new_buff");
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}

		memcpy(new_buff, data, size);
		new_buff[size] = '\0';

		cloud_prov->broker_url = new_buff;
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		cloud_prov->broker_url = NULL;
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("Server Url : read fail");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_SERVER_URL, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_SERVER_PORT */
	ret = _iot_nv_read_data(IOT_NVD_SERVER_PORT, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		cloud_prov->broker_port = atoi(data);
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		cloud_prov->broker_port = -1;
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("Server Port : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_SERVER_PORT, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_LABEL */
	memset(data, 0, DATA_SIZE);

	ret = _iot_nv_read_data(IOT_NVD_LABEL, data, DATA_SIZE, NULL);
	if (ret == IOT_ERROR_NONE) {
		size = strlen(data);
		new_buff = (char *)iot_os_malloc(size + 1);
		if (new_buff == NULL) {
			IOT_WARN("failed to malloc for new_buff");
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}

		memcpy(new_buff, data, size);
		new_buff[size] = '\0';

		cloud_prov->label = new_buff;
	} else if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
		cloud_prov->label = NULL;
		ret = IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("Label : read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_LABEL, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

exit:
	iot_os_free(data);

	return ret;
}

iot_error_t iot_nv_set_cloud_prov_data(struct iot_cloud_prov_data* cloud_prov)
{
	HIT();
	IOT_WARN_CHECK(cloud_prov == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_CLOUD_PROV_STATUS
	 * IOT_NVD_SERVER_URL
	 * IOT_NVD_SERVER_PORT
	 * IOT_NVD_LOCATION_ID
	 * IOT_NVD_ROOM_ID
	 * IOT_NVD_LABEL
	 */
	iot_error_t ret;
	const int DATA_SIZE = (IOT_NVD_MAX_DATA_LEN / 2) + 1;
	size_t size;
	int state;
	char* data = NULL;

	data = malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	/* IOT_NVD_CLOUD_PROV_STATUS - NONE */
	size = 4;
	memcpy(data, "NONE", size);
	data[size] = '\0';

	ret = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, data, size);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Cloud Prov Status : write failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_CLOUD_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_SERVER_URL */
	if (cloud_prov->broker_url == NULL) {
		iot_nv_erase(IOT_NVD_SERVER_URL);
	} else {
		size = strlen(cloud_prov->broker_url);

		ret = _iot_nv_write_data(IOT_NVD_SERVER_URL, cloud_prov->broker_url, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("Server Url : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_SERVER_URL, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_SERVER_PORT */
	state = snprintf(data, DATA_SIZE, "%d", cloud_prov->broker_port);
	if (state <= 0) {
		IOT_DEBUG("Server Port : data load failed from prov structure");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	size = state;
	data[size] = '\0';

	ret = _iot_nv_write_data(IOT_NVD_SERVER_PORT, data, size);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Server Port : write failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_SERVER_PORT, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	/* IOT_NVD_LABEL */
	if (cloud_prov->label == NULL) {
		iot_nv_erase(IOT_NVD_LABEL);
	} else {
		size = strlen(cloud_prov->label);
		ret = _iot_nv_write_data(IOT_NVD_LABEL, cloud_prov->label, size);
		if (ret != IOT_ERROR_NONE) {
			IOT_DEBUG("Label : write failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_LABEL, __LINE__);
			ret = IOT_ERROR_NV_DATA_ERROR;
			goto exit;
		}
	}

	/* IOT_NVD_CLOUD_PROV_STATUS - DONE */
	size = 4;
	memcpy(data, "DONE", size);
	data[size] = '\0';

	ret = _iot_nv_write_data(IOT_NVD_CLOUD_PROV_STATUS, data, size);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("Cloud Prov Status : write failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_CLOUD_PROV_STATUS, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

exit:
	free(data);

	return ret;
}

iot_error_t iot_nv_get_certificate(iot_security_cert_id_t cert_id, char** cert, size_t* len)
{
	iot_error_t ret;
	iot_security_context_t *security_context;
	iot_security_buffer_t cert_buf;

	HIT();
	IOT_WARN_CHECK((cert == NULL || len == NULL), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	security_context = _iot_nv_io_storage_init();
	if (security_context == NULL) {
		IOT_ERROR("failed to init storage");
		return IOT_ERROR_NV_DATA_ERROR;
	}

	ret = iot_security_manager_init(security_context);
	if (ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to init manager");
		return IOT_ERROR_NV_DATA_ERROR;
	}

	ret = iot_security_manager_get_certificate(security_context, cert_id, &cert_buf);
	if (ret != IOT_ERROR_NONE) {
		IOT_ERROR("failed to get cert(%d), ret = %d", cert_id, ret);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	*cert = (char *)cert_buf.p;
	*len = cert_buf.len;

	(void)iot_security_manager_deinit(security_context);
	(void)_iot_nv_io_storage_deinit(security_context);

	return IOT_ERROR_NONE;
}

static char *_iot_nv_trim_certificate(const char *cert, size_t cert_len)
{
	const char *certificate_prefix = "-----BEGIN CERTIFICATE-----";
	const char *certificate_suffix = "-----END CERTIFICATE-----";
	char *trimmed_cert = NULL;
	const char *cert_head = NULL;
	const char *cert_tail = NULL;
	int trim_idx;

	cert_head = strstr(cert, certificate_prefix);
	if (cert_head == NULL) {
		cert_head = &cert[0];
	}
	else {
		cert_head += strlen(certificate_prefix);
	}

	cert_tail = strstr(cert, certificate_suffix);
	if (cert_tail == NULL) {
		cert_tail = &cert[cert_len];
	}

	trimmed_cert = (char *)malloc(cert_tail - cert_head + 1);
	for (trim_idx = 0; cert_head != cert_tail; cert_head++) {
		if (cert_head[0] == '\n' || cert_head[0] == '\r') {
			continue;
		}
		trimmed_cert[trim_idx++] = cert_head[0];
	}
	trimmed_cert[trim_idx] = '\0';

	return trimmed_cert;
}

iot_error_t _iot_nv_get_certificate_serial_number(char **cert_sn)
{
	mbedtls_x509_crt cert;
	char *cert_buf = NULL;
	char *cert_der = NULL;
	char *cert_sn_buf = NULL;
	char *trimmed_cert = NULL;
	size_t cert_len;
	size_t cert_der_len;
	size_t cert_sn_len;
	size_t trimmed_cert_len;
	char buf[2];
	int idx, buf_idx;
	int ret;

	ret = iot_nv_get_certificate(IOT_SECURITY_CERT_ID_DEVICE, &cert_buf, &cert_len);
	if (ret) {
		IOT_ERROR("iot_nv_get_certificate = %d", ret);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	trimmed_cert = _iot_nv_trim_certificate(cert_buf, cert_len);
	if (trimmed_cert == NULL) {
		iot_os_free(cert_buf);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	trimmed_cert_len = strlen(trimmed_cert);
	cert_der = (char *)malloc(trimmed_cert_len);
	if (!cert_der) {
		IOT_ERROR("malloc failed for cert_der");
		return IOT_ERROR_NV_DATA_ERROR;
	}
	memset(cert_der, 0, trimmed_cert_len);
	ret = iot_security_base64_decode((const unsigned char *)trimmed_cert, trimmed_cert_len, (unsigned char *)cert_der, trimmed_cert_len, &cert_der_len);
	if (ret) {
		IOT_ERROR( "certification parse failed : 0x%x", -ret);
		iot_os_free(cert_der);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	mbedtls_x509_crt_init(&cert);
	ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)cert_der, cert_der_len);
	if (ret) {
		IOT_ERROR( "certification parse failed : 0x%x", -ret);
		iot_os_free(cert_der);
		mbedtls_x509_crt_free(&cert);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	cert_sn_len = cert.serial.len * 2 + 1;
	cert_sn_buf = (char *)malloc(cert_sn_len);
	if (!cert_sn) {
		IOT_ERROR("malloc failed for cert_sn_buf");
		iot_os_free(cert_der);
		mbedtls_x509_crt_free(&cert);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	memset(cert_sn_buf, 0, cert_sn_len);
	for (idx=0; idx<cert.serial.len; idx++) {
		buf[0] = cert.serial.p[idx] >> 4;
		buf[1] = cert.serial.p[idx] & 0x0f;
		for (buf_idx=0; buf_idx<2; buf_idx++){
			if (buf[buf_idx] > 9 && buf[buf_idx] < 16) {
				cert_sn_buf[idx * 2 + buf_idx] = buf[buf_idx] - 10 + 'a';
			}
			else if (buf[buf_idx] >= 0 && buf[buf_idx] < 10) {
				cert_sn_buf[idx * 2 + buf_idx] = buf[buf_idx] + '0';
			}
			else{
				IOT_ERROR("certification serial number parse failed : 0x%x", cert.serial.p[idx]);
				iot_os_free(cert_der);
				iot_os_free(cert_sn_buf);
				mbedtls_x509_crt_free(&cert);
				return IOT_ERROR_NV_DATA_ERROR;
			}
		}
	}

	*cert_sn = cert_sn_buf;
	iot_os_free(cert_der);
	mbedtls_x509_crt_free(&cert);
	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_get_device_id(char** device_id, size_t* len)
{
	HIT();
	IOT_WARN_CHECK((device_id == NULL || len == NULL), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_DEVICE_ID
	 */
	iot_error_t ret;
	const int DATA_SIZE = IOT_NVD_MAX_UID_LEN + 1;
	unsigned int size;
	char* data = NULL;
	char* new_buff = NULL;

	data = iot_os_malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	ret = _iot_nv_read_data(IOT_NVD_DEVICE_ID, data, DATA_SIZE, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_DEVICE_ID, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	size = strlen(data);
	new_buff = (char*)iot_os_malloc(size + 1);
	if (new_buff == NULL) {
		IOT_WARN("failed to malloc for new_buff");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	memcpy(new_buff, data, size);
	new_buff[size] = '\0';

	*device_id = new_buff;
	*len = size;

exit:
	iot_os_free(data);

	return ret;
}

iot_error_t iot_nv_set_device_id(const char* device_id)
{
	HIT();
	IOT_WARN_CHECK(device_id == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_DEVICE_ID
	 */
	iot_error_t ret;

	ret = _iot_nv_write_data(IOT_NVD_DEVICE_ID, device_id, strlen(device_id));
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("write fail");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_DEVICE_ID, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
	}

	return ret;
}

iot_error_t iot_nv_get_serial_number(char** sn, size_t* len)
{
	HIT();
	IOT_WARN_CHECK((sn == NULL || len == NULL), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");

	iot_error_t ret;
	unsigned int size;
	const int DATA_SIZE = IOT_NVD_MAX_SN_LEN + 1;
	char* data = NULL;
	char* new_buff = NULL;

	data = iot_os_malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	ret = _iot_nv_read_data(IOT_NVD_SERIAL_NUM, data, DATA_SIZE, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_SERIAL_NUM, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	size = strlen(data);
	new_buff = (char*)iot_os_malloc(size + 1);
	if (new_buff == NULL) {
		IOT_WARN("failed to malloc for new_buff");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	memcpy(new_buff, data, size);
	new_buff[size] = '\0';

	*sn = new_buff;
	*len = size;

exit:
	iot_os_free(data);

	return ret;
}

iot_error_t iot_nv_get_misc_info(char** misc_info, size_t* len)
{
	HIT();
	IOT_WARN_CHECK((misc_info == NULL || len == NULL), IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_MISC_INFO
	 */
	iot_error_t ret;
	const int DATA_SIZE = IOT_NVD_MAX_DATA_LEN + 1;
	unsigned int size;
	char* data = NULL;
	char* new_buff = NULL;

	data = malloc(sizeof(char) * DATA_SIZE);
	IOT_WARN_CHECK(data == NULL, IOT_ERROR_NV_DATA_ERROR, "memory alloc fail");

	ret = _iot_nv_read_data(IOT_NVD_MISC_INFO, data, DATA_SIZE, NULL);
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("read failed");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_READ_FAIL, IOT_NVD_MISC_INFO, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	size = strlen(data);
	new_buff = (char*)malloc(size + 1);
	if (new_buff == NULL) {
		IOT_WARN("failed to malloc for new_buff");
		ret = IOT_ERROR_NV_DATA_ERROR;
		goto exit;
	}

	memcpy(new_buff, data, size);
	new_buff[size] = '\0';

	*misc_info = new_buff;
	*len = size;

exit:
	free(data);

	return ret;
}

iot_error_t iot_nv_set_misc_info(const char* misc_info)
{
	HIT();
	IOT_WARN_CHECK(misc_info == NULL, IOT_ERROR_INVALID_ARGS, "Invalid args 'NULL'");
	/*
	 * Todo :
	 * IOT_NVD_MISC_INFO
	 */
	iot_error_t ret;

	ret = _iot_nv_write_data(IOT_NVD_MISC_INFO, misc_info, strlen(misc_info));
	if (ret != IOT_ERROR_NONE) {
		IOT_DEBUG("write fail");
		IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_WRITE_FAIL, IOT_NVD_MISC_INFO, __LINE__);
		ret = IOT_ERROR_NV_DATA_ERROR;
	}

	return ret;
}

iot_error_t iot_nv_erase(iot_nvd_t nv_type)
{
	HIT();
	IOT_WARN_CHECK((nv_type < 0 || nv_type >= IOT_NVD_MAX), IOT_ERROR_INVALID_ARGS, "Invalid args");

	iot_error_t ret;

	ret = _iot_nv_remove_data(nv_type);
	if (ret != IOT_ERROR_NONE) {
		if (ret == IOT_ERROR_NV_DATA_NOT_EXIST) {
			IOT_DEBUG("file does not exist");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_NOT_EXIST, nv_type, __LINE__);
			return IOT_ERROR_NV_DATA_NOT_EXIST;
		} else {
			IOT_DEBUG("file remove failed");
			IOT_DUMP(IOT_DEBUG_LEVEL_DEBUG, IOT_DUMP_NV_DATA_ERASE_FAIL, nv_type, __LINE__);
			return IOT_ERROR_NV_DATA_ERROR;
		}
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_nv_get_static_certificate(iot_security_cert_id_t cert_id, iot_security_buffer_t *output_buf)
{
	unsigned char *data = NULL;
	unsigned char *cert;
	unsigned int cert_len;

	IOT_DEBUG("cert id = %d", cert_id);

	if (!output_buf) {
		IOT_ERROR("output buf is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	switch (cert_id) {
	case IOT_SECURITY_CERT_ID_ROOT_CA:
		cert = st_root_ca;
		cert_len = st_root_ca_len;
		break;
	default:
		IOT_ERROR("%d is not a supported static certificate", cert_id);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	data = (unsigned char *)iot_os_malloc(cert_len + 1);
	if (!data) {
		IOT_ERROR("failed to malloc for static nv");
		return IOT_ERROR_MEM_ALLOC;
	}

	memcpy(data, cert, cert_len);
	data[cert_len] = '\0';

	output_buf->p = data;
	output_buf->len = cert_len;

	return IOT_ERROR_NONE;
}

#if !defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
iot_error_t iot_nv_get_data_from_device_info(iot_nvd_t nv_id, iot_security_buffer_t *output_buf)
{
	iot_error_t err;
	const char *di_name;
	char *data = NULL;

	IOT_DEBUG("nv id = %d", nv_id);

	if (!output_buf) {
		IOT_ERROR("output buffer is null");
		return IOT_ERROR_INVALID_ARGS;
	}

	memset(output_buf, 0, sizeof(iot_security_buffer_t));

	switch (nv_id) {
	case IOT_NVD_PRIVATE_KEY:
		di_name = name_privateKey;
		break;
	case IOT_NVD_PUBLIC_KEY:
		di_name = name_publicKey;
		break;
	case IOT_NVD_ROOT_CA_CERT:
		di_name = name_rootCaCert;
		break;
	case IOT_NVD_SUB_CA_CERT:
		di_name = name_subCaCert;
		break;
	case IOT_NVD_DEVICE_CERT:
		di_name = name_deviceCert;
		break;
	case IOT_NVD_SERIAL_NUM:
		di_name = name_serialNumber;
		break;
	default:
		IOT_ERROR("%d is not a device info nv", nv_id);
		return IOT_ERROR_NV_DATA_ERROR;
	}

	err = iot_api_read_device_identity(device_nv_info, device_nv_info_len, di_name, &data);
	if (err) {
		IOT_ERROR("iot_api_read_device_identity = %d", err);
		return err;
	}

	if (data) {
		output_buf->p = (unsigned char *)data;
		output_buf->len = strlen(data);
	}

	return IOT_ERROR_NONE;
}
#endif
