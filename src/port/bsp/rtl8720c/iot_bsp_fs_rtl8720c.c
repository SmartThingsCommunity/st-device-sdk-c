/******************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
 *
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 ******************************************************************/
#include "flash_api.h"
#include "device_lock.h"
#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"
//#include "platform.h"
#include "FreeRTOS.h"
#include "semphr.h"
#include "cmsis_os.h"

typedef struct nv_item_table
{
	const char* name;
	size_t size;
	size_t addr;
} nv_item_table_s;

#define FLASH_USR_STORAGE_BASE        0x00110000
#define FLASH_SECTOR_SIZE             4096
#define FLASH_SECTOR_SHIFT	          12

#define OP_OK		1
#define OP_FAIL	-1

#define MAX_NV_ITEM_CNT				19


nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{"WifiProvStatus", 65, 0},  // WifiProvStatus
	{"IotAPSSID", 65, 0},   // IotAPSSID
	{"IotAPPASS", 65, 0},   // IotAPPASS
	{"IotAPBSSID", 65, 0},   // IotAPBSSID
	{"IotAPAuthType", 65, 0},   // IotAPAuthType

	/* for cloud prov data */
	{"CloudProvStatus", 1025, 0},   // CloudProvStatus
	{"ServerURL", 1025, 0},  // ServerURL
	{"ServerPort", 37, 0},   // ServerPort
	{"Label", 37, 0},  // Label

	{"DeviceID", 129, 0},  // DeviceID
	{"MiscInfo", 2048, 0},   // MiscInfo

	/* stored in stnv partition (manufacturer data) */
	{"PrivateKey", 2048, 0},   // PrivateKey
	{"PublicKey", 2048, 0},   // PublicKey
	{"PKType", 37, 0},   // PKType
	{"RootCert", 2048, 0},  // RootCert
	{"SubCert", 2048, 0},   // SubCert
	{"DeviceCert", 2048, 0},   // DeviceCert
	{"ClaimID", 37, 0},   // ClaimID
	{"SerialNum", 37, 0},   // SerialNum

};

static int get_nv_idx(char *str_name)
{
	int i;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (0 == strcmp(str_name, nv_table[i].name))
			return i;
	}
	return OP_FAIL;
}

static void nv_data_preload(void)
{
	int i;
	size_t last_address;

	last_address = FLASH_USR_STORAGE_BASE;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		IOT_DEBUG("Add storage : name %s, addr %X, size %d", nv_table[i].name, nv_table[i].addr, nv_table[i].size);
	}
}

static void nv_storage_init(void)
{
	static bool intitialized;

	if (intitialized)
		return;

	nv_data_preload();
	intitialized = true;
}

static int nv_storage_read(const char *store, uint8_t *buf, size_t *size)
{
	flash_t flash;
	int ret, idx;
	size_t cmp_size;
	uint8_t *tempbuf;
	size_t read_size;

	nv_storage_init();
	IOT_INFO("read %s size %d", store, *size);

	idx = get_nv_idx(store);
	if (idx < 0) {
		IOT_ERROR("The %s is not found\n", store);
		return OP_FAIL;
	}
	read_size = (nv_table[idx].size > *size) ? *size : nv_table[idx].size;
	IOT_INFO("read address:0x%x, size:%d\n",nv_table[idx].addr, read_size);
	device_mutex_lock(RT_DEV_LOCK_FLASH);
	ret = flash_stream_read(&flash, nv_table[idx].addr, read_size, buf);
	if (ret != OP_OK) {
		IOT_ERROR("Flash read %s fail", store);
		device_mutex_unlock(RT_DEV_LOCK_FLASH);
		return OP_FAIL;
	}
	device_mutex_unlock(RT_DEV_LOCK_FLASH);

	cmp_size = read_size;
	tempbuf = malloc(cmp_size);
	if (!tempbuf) {
		IOT_ERROR("Failed to malloc for tempbuf");
		return OP_FAIL;
	}
	memset(tempbuf, 0xFF, cmp_size);
	if (memcmp(tempbuf, buf, cmp_size) == 0) {
		IOT_ERROR("The flash data is invalid\n");
		free(tempbuf);
		return -2;
	}
	*size = read_size;
	free(tempbuf);
	return 0;
}

static void specail_op_before_flash_write()
{
	char buf[4] = {'\0',};
	int len = 3;
	flash_t flash;

	device_mutex_lock(RT_DEV_LOCK_FLASH);
	int id =  flash_read_id(&flash, (uint8_t *)buf, len);
	IOT_DEBUG("id is %d [%d %d %d]\r\n", id, buf[0], buf[1], buf[2]);
	int status = flash_get_status(&flash);
	IOT_DEBUG("flash status is %d\r\n", status);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
}

static int _flash_write(size_t addr, size_t size, uint8_t *buf)
{
	int last_sector, first_sector, ret;
	uint8_t *backup;
	flash_t flash;
	size_t written;
	size_t start_addr;
	size_t pos;

	first_sector = (addr - FLASH_USR_STORAGE_BASE) >> FLASH_SECTOR_SHIFT;
	last_sector = ((addr + size - FLASH_USR_STORAGE_BASE) >> FLASH_SECTOR_SHIFT);

	backup = malloc(FLASH_SECTOR_SIZE);
	if (!backup) {
		IOT_ERROR("Failed to malloc for backup");
		return OP_FAIL;
	}

	specail_op_before_flash_write();
	device_mutex_lock(RT_DEV_LOCK_FLASH);
	do {
		start_addr = FLASH_USR_STORAGE_BASE + (first_sector << FLASH_SECTOR_SHIFT);
		ret = flash_stream_read(&flash, start_addr, FLASH_SECTOR_SIZE, backup);
		if (ret != OP_OK) {
			free(backup);
			IOT_ERROR("Flash read %X fail", start_addr);
			device_mutex_unlock(RT_DEV_LOCK_FLASH);
			return OP_FAIL;
		}
		pos = addr - start_addr;
		written = (size > (FLASH_SECTOR_SIZE - pos)) ? (FLASH_SECTOR_SIZE - pos) : size;
		if (memcmp(backup+pos, buf, written) != 0) {
			memcpy(backup+pos, buf, written);
			flash_erase_sector(&flash, start_addr);
			ret = flash_stream_write(&flash, start_addr, FLASH_SECTOR_SIZE, backup);
			if (ret != OP_OK) {
				free(backup);
				IOT_ERROR("failed to write storage addr %X", start_addr);
				device_mutex_unlock(RT_DEV_LOCK_FLASH);
				return OP_FAIL;
			}
		}
		addr += written;
		size -= written;
		first_sector ++;
	} while (first_sector <= last_sector);

	free(backup);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
	return written;
}

static long nv_storage_write(const char *store, uint8_t *buf, size_t size)
{
	flash_t flash;
	int ret, idx;

	nv_storage_init();
	IOT_INFO("write %s size %d", store, size);

	idx = get_nv_idx(store);
	if (idx < 0) {
		IOT_ERROR("The [%s] is not found\n", store);
		return OP_FAIL;
	}

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %d is smaller than size of write buffer %d\n", store, nv_table[idx].size, size);
		return OP_FAIL;
	}

	ret = _flash_write(nv_table[idx].addr, size, buf);
	if (ret < 0) {
		IOT_ERROR("Failed to write %s", store);
		return OP_FAIL;
	}
	return size;
}

static int nv_storage_erase(const char *store)
{
	int ret, idx;
	uint8_t *buf;

	nv_storage_init();

	idx = get_nv_idx(store);
	if (idx < 0) {
		IOT_ERROR("The [%s] is not found\n", store);
		return OP_FAIL;
	}

	buf = malloc(nv_table[idx].size);
	if (!buf){
		IOT_INFO("Failed to malloc for buf");
		return OP_FAIL;
	}
	memset(buf, 0xFF, nv_table[idx].size);
	ret = _flash_write(nv_table[idx].addr, nv_table[idx].size, buf);
	if (ret < 0) {
		IOT_ERROR("Failed to erase %s", store);
	}
	free(buf);
	return ret;
}

iot_error_t iot_bsp_fs_init()
{
	nv_storage_init();
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	int ret = 0;
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, size_t *length)
{
	int ret;

	if (!buffer || *length <= 0 || *length > FLASH_SECTOR_SIZE)
		return IOT_ERROR_FS_READ_FAIL;
	ret = nv_storage_read(handle.filename, buffer, length);
	IOT_DEBUG_CHECK(ret < -1, IOT_ERROR_FS_NO_FILE, "nvs no file");
	IOT_ERROR_CHECK(ret < 0, IOT_ERROR_FS_READ_FAIL, "nvs read fail ");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0 || length > FLASH_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, data, length + 1);
	IOT_ERROR_CHECK(ret == OP_FAIL, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail ");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	int ret;

	ret = nv_storage_erase(filename);
	IOT_ERROR_CHECK(ret == OP_FAIL, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail ");
	return IOT_ERROR_NONE;
}
