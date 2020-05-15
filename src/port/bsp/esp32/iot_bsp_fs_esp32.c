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

#include <stdlib.h>
#include <string.h>
#include <esp_err.h>
#include <nvs_flash.h>

#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_crypto.h"
#include "iot_debug.h"

#define STDK_NV_DATA_PARTITION "stnv"
#define STDK_NV_DATA_NAMESPACE "stdk"

static const char* _get_error_string(esp_err_t err) {

	switch(err) {
	case ESP_OK:
		return "Ok";
	case ESP_ERR_NVS_NO_FREE_PAGES:
		return "No Free Page";
	case ESP_ERR_NOT_FOUND:
		return "Partition Not Found";
	case ESP_ERR_NVS_NOT_INITIALIZED:
		return "NVS Not Initialized";
	case ESP_ERR_NVS_PART_NOT_FOUND:
		return "Partition Not Found";
	case ESP_ERR_NVS_NOT_FOUND:
		return "Namespace/Key Not Found";
	case ESP_ERR_NVS_INVALID_NAME:
		return "Namespace/Key Name Invalid";
	case ESP_ERR_NVS_INVALID_HANDLE:
		return "Invalid Handle";
	case ESP_ERR_NVS_INVALID_LENGTH:
		return "Invalid Length";
	case ESP_ERR_NVS_READ_ONLY:
		return "Read-only Handle";
	case ESP_ERR_NVS_NOT_ENOUGH_SPACE:
		return "Not Enough Space";
	case ESP_ERR_NVS_REMOVE_FAILED:
		return "Remove Failed";
	default:
		return "Unknown";
	}
}

iot_error_t iot_bsp_fs_init()
{
	esp_err_t ret = nvs_flash_init();
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	ret = nvs_flash_init_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", STDK_NV_DATA_PARTITION, _get_error_string(ret));
#endif
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	esp_err_t ret = nvs_flash_deinit_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_DEINIT_FAIL, "nvs deinit failed [%s]", _get_error_string(ret));
#endif
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode;

	if (mode == FS_READONLY) {
		nvs_open_mode = NVS_READONLY;
	} else {
		nvs_open_mode = NVS_READWRITE;
	}

	esp_err_t ret = nvs_open(STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	if (ret == ESP_OK) {
		handle->fd = nvs_handle;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("nvs open failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
}

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode = NVS_READONLY;

	esp_err_t ret = nvs_open_from_partition(STDK_NV_DATA_PARTITION, STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	if (ret == ESP_OK) {
		handle->fd = nvs_handle;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("nv open failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
}
#endif

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
	esp_err_t ret;
	size_t required_size;

	ret = nvs_get_str(handle.fd, handle.filename, NULL, &required_size);
	if (ret == ESP_ERR_NVS_NOT_FOUND) {
		IOT_DEBUG("not found '%s'", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	} else if (ret != ESP_OK) {
		IOT_DEBUG("nvs read failed [%s]", _get_error_string(ret));
		return IOT_ERROR_FS_READ_FAIL;
	}

	char* data = malloc(required_size);
	ret = nvs_get_str(handle.fd, handle.filename, data, &required_size);
	if (ret != ESP_OK) {
		IOT_DEBUG("nvs read failed [%s]", _get_error_string(ret));
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	}

	if (*length <= required_size) {
		IOT_ERROR("length is not enough (%d < %d)", *length, required_size);
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	} else {
		memcpy(buffer, data, required_size);
		*length = required_size;
	}

	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, unsigned int length)
{
	esp_err_t ret = nvs_set_str(handle.fd, handle.filename, data);
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_WRITE_FAIL, "nvs write failed [%s]", _get_error_string(ret));

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	nvs_close(handle.fd);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	if (filename == NULL) {
		return IOT_ERROR_INVALID_ARGS;
	}

	nvs_handle nvs_handle;
	nvs_open_mode nvs_open_mode = NVS_READWRITE;

	esp_err_t ret = nvs_open(STDK_NV_DATA_NAMESPACE, nvs_open_mode, &nvs_handle);
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_REMOVE_FAIL, "nvs open failed [%s]", _get_error_string(ret));

	ret = nvs_erase_key(nvs_handle, filename);
	if (ret != ESP_OK) {
		IOT_DEBUG("nvs erase failed [%s]", _get_error_string(ret));
		nvs_close(nvs_handle);
		if (ret == ESP_ERR_NVS_NOT_FOUND) {
			return IOT_ERROR_FS_NO_FILE;
		} else {
			return IOT_ERROR_FS_REMOVE_FAIL;
		}
	}

	nvs_close(nvs_handle);

	return IOT_ERROR_NONE;
}
