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
#include "iot_debug.h"
#if defined(CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION)
#include "security/backend/lib/iot_security_ss.h"
#endif

#define STDK_NV_DATA_PARTITION "stnv"
#define STDK_NV_DATA_NAMESPACE "stdk"

#if defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_WARN) || defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_DEBUG)\
	|| defined(CONFIG_STDK_IOT_CORE_LOG_LEVEL_ERROR)
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
#endif

#if defined(CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION)
struct fs_migration {
	const char *filename;
	char *data;
	size_t filesize;
};

static iot_error_t _iot_bsp_fs_encryption(char *partition, int do_erase)
{
	iot_error_t ret = IOT_ERROR_FS_ENCRYPT_INIT;
	iot_bsp_fs_handle_t fs_handle;
	esp_err_t esp_ret;
	nvs_handle handle;
	size_t filesize;
	const char *filename;
	char *magic = STDK_NV_DATA_PARTITION;
	const char *magic_data = "encrypted";
	struct fs_migration backup[IOT_NVD_MAX] = {0};
	struct fs_migration *ptr;
	int i;

	esp_ret = nvs_open_from_partition(partition, STDK_NV_DATA_NAMESPACE, NVS_READWRITE, &handle);
	if (esp_ret != ESP_OK) {
		IOT_ERROR("failed to open '%s' partition", partition);
		return IOT_ERROR_FS_ENCRYPT_INIT;
	}

	esp_ret = nvs_get_str(handle, magic, NULL, &filesize);
	if (esp_ret == ESP_OK) {
		IOT_INFO("'%s' is encrypted", partition);
		nvs_close(handle);
		return IOT_ERROR_NONE;
	}

	for (i = 0; i < IOT_NVD_MAX; i++) {
		filename = iot_bsp_nv_get_data_path(i);
		if (filename == NULL) {
			IOT_DEBUG("nv index '%d' is not registered", i);
			continue;
		}

		esp_ret = nvs_get_str(handle, filename, NULL, &filesize);
		if (esp_ret != ESP_OK) {
			IOT_DEBUG("'%s' does not exist", filename);
			continue;
		}

		ptr = &backup[i];

		ptr->data = (char *)malloc(filesize);
		if (ptr->data == NULL) {
			IOT_ERROR("malloc failed for fs encryption");
			ret = IOT_ERROR_MEM_ALLOC;
			goto exit;
		}

		esp_ret = nvs_get_str(handle, filename, ptr->data, &filesize);
		if (esp_ret != ESP_OK) {
			IOT_ERROR("failed to read '%s'", filename);
			goto exit;
		}

		ptr->filename = filename;
		ptr->filesize = filesize;
	}

	if (do_erase) {
		nvs_close(handle);

		nvs_flash_deinit_partition(partition);

		esp_ret = nvs_flash_erase_partition(partition);
		if (esp_ret != ESP_OK) {
			IOT_ERROR("failed to erase '%s' partition", partition);
			goto exit_backup_free;
		}

		esp_ret = nvs_flash_init_partition(partition);
		if (esp_ret != ESP_OK) {
			IOT_ERROR("failed to init '%s' partition", partition);
			goto exit_backup_free;
		}

		esp_ret = nvs_open_from_partition(partition, STDK_NV_DATA_NAMESPACE, NVS_READWRITE, &handle);
		if (esp_ret != ESP_OK) {
			IOT_WARN("failed to open '%s' partition", partition);
			goto exit_backup_free;
		}
	}

	for (i = 0; i < IOT_NVD_MAX; i++) {
		ptr = &backup[i];

		if (ptr->data == NULL)
			continue;

		fs_handle.fd = handle;
		snprintf(fs_handle.filename, sizeof(fs_handle.filename), "%s", ptr->filename);

		ret = iot_bsp_fs_write(fs_handle, ptr->data, ptr->filesize);
		if (ret != IOT_ERROR_NONE) {
			IOT_ERROR("failed to write encrypted '%s'", ptr->filename);
			goto exit;
		}

		IOT_INFO("'%s' is encrypted", ptr->filename);
	}

	esp_ret = nvs_set_str(handle, magic, magic_data);
	if (esp_ret != ESP_OK) {
		IOT_ERROR("failed to mark magic");
		goto exit;
	}

	ret = IOT_ERROR_NONE;
exit:
	nvs_close(handle);
exit_backup_free:
	for (i = 0; i < IOT_NVD_MAX; i++) {
		if (backup[i].data != NULL) {
			free(backup[i].data);
		}
	}

	return ret;
}

static iot_error_t _iot_bsp_fs_init_encryption(void)
{
	iot_error_t ret;
	char *partition;

	partition = NVS_DEFAULT_PART_NAME;
	ret = _iot_bsp_fs_encryption(partition, 0);
	if (ret != IOT_ERROR_NONE) {
		IOT_ERROR("encryption failed for %s, ret = %d", partition, ret);
		return ret;
	}
#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	partition = STDK_NV_DATA_PARTITION;
	ret = _iot_bsp_fs_encryption(partition, 1);
	if (ret != IOT_ERROR_NONE) {
		IOT_ERROR("encryption failed for %s, ret = %d", partition, ret);
		return ret;
	}
#endif
	return IOT_ERROR_NONE;
}
#endif

iot_error_t iot_bsp_fs_init()
{
	esp_err_t ret = nvs_flash_init();
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", NVS_DEFAULT_PART_NAME, _get_error_string(ret));

#if defined(CONFIG_STDK_IOT_CORE_SUPPORT_STNV_PARTITION)
	ret = nvs_flash_init_partition(STDK_NV_DATA_PARTITION);
	IOT_WARN_CHECK(ret != ESP_OK, IOT_ERROR_INIT_FAIL, "%s init failed [%s]", STDK_NV_DATA_PARTITION, _get_error_string(ret));
#endif
#if defined(CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION)
	iot_error_t err = _iot_bsp_fs_init_encryption();
	IOT_ERROR_CHECK(err != IOT_ERROR_NONE, err, "encryption init failed");
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

#if defined(CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION)
	iot_error_t err;
	char *data;
	unsigned char *decbuf = NULL;
	size_t olen;

	ret = nvs_get_blob(handle.fd, handle.filename, NULL, &required_size);
	if (ret == ESP_ERR_NVS_NOT_FOUND) {
		IOT_DEBUG("not found '%s'", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	} else if (ret != ESP_OK) {
		return IOT_ERROR_FS_READ_FAIL;
	}

	data = malloc(required_size);
	if (data == NULL) {
		IOT_ERROR("malloc failed for fs read");
		return IOT_ERROR_MEM_ALLOC;
	}

	ret = nvs_get_blob(handle.fd, handle.filename, data, &required_size);
	if (ret != ESP_OK) {
		IOT_ERROR("read '%s' failed [%s]", handle.filename, _get_error_string(ret));
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	}

	err = iot_security_ss_decrypt((unsigned char *)data, required_size, &decbuf, &olen);
	if (err) {
		IOT_ERROR("iot_crypto_ss_decrypt = %d", err);
		free(data);
		return IOT_ERROR_FS_DECRYPT_FAIL;
	}

	if (*length < olen) {
		IOT_ERROR("length is not enough (%d < %d)", *length, olen);
		free(decbuf);
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	} else {
		memcpy(buffer, decbuf, olen);
		*length = olen;
	}

	free(decbuf);
#else
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

	if (*length < required_size) {
		IOT_ERROR("length is not enough (%d < %d)", *length, required_size);
		free(data);
		return IOT_ERROR_FS_READ_FAIL;
	} else {
		memcpy(buffer, data, required_size);
		*length = required_size;
	}
#endif
	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, size_t length)
{
#if defined(CONFIG_STDK_IOT_CORE_FS_SW_ENCRYPTION)
	esp_err_t ret;
	iot_error_t err;
	unsigned char *encbuf = NULL;
	size_t data_len = strlen(data) + 1;
	size_t olen;

	err = iot_security_ss_encrypt((unsigned char *)data, data_len, &encbuf, &olen);
	if (err) {
		IOT_ERROR("iot_crypto_ss_encrypt = %d", err);
		return IOT_ERROR_FS_ENCRYPT_FAIL;
	}

	ret = nvs_set_blob(handle.fd, handle.filename, (const void *)encbuf, olen);
	if (ret != ESP_OK) {
		IOT_ERROR("write '%s' failed [%s]", handle.filename, _get_error_string(ret));
		free(encbuf);
		return IOT_ERROR_FS_WRITE_FAIL;
	}
	free(encbuf);
#else
	esp_err_t ret = nvs_set_str(handle.fd, handle.filename, data);
#endif
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail [%s]", _get_error_string(ret));

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
	IOT_DEBUG_CHECK(ret != ESP_OK, IOT_ERROR_FS_REMOVE_FAIL, "nvs open fail [%s]", _get_error_string(ret));

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
