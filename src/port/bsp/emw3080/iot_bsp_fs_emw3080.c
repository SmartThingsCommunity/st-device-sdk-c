/***************************************************************************
 *
 * Copyright 2020 Samsung Electronics All Rights Reserved.
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
#include "iot_bsp_fs.h"
#include "iot_bsp_nv_data.h"
#include "iot_debug.h"
#include "mico.h"
#include "mico_board.h"

typedef struct nv_item_table
{
	const char* name;
	size_t size;
	size_t addr;
} nv_item_table_s;

#define MAX_NV_ITEM_CNT			19
#define STDK_NV_SECTOR_SIZE            (0x1000)

nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{"WifiProvStatus", 65, 0},  // WifiProvStatus
	{"IotAPSSID", 65, 0},   // IotAPSSID
	{"IotAPPASS", 65, 0},   // IotAPPASS
	{"IotAPBSSID", 65, 0},   // IotAPBSSID
	{"IotAPAuthType", 65, 0},   // IotAPAuthType

	/* for cloud prov data */
	{"CloudProvStatus", 65, 0},   // CloudProvStatus
	{"ServerURL", 512, 0},  // ServerURL
	{"ServerPort", 37, 0},   // ServerPort
	{"Label", 37, 0},  // Label

	{"DeviceID", 129, 0},  // DeviceID
	{"MiscInfo", 2048, 0},   // PrivateKey

	/* stored in stnv partition (manufacturer data) */
	{"PrivateKey", 2048, 0},   // PrivateKey
	{"PublicKey", 2048, 0},   // PublicKey
	{"RootCert", 2048, 0},  // RootCert
	{"SubCert", 2048, 0},   // SubCert
	{"DeviceCert", 2048, 0},   // DeviceCert
	{"PKType", 37, 0},	 // PKType
	{"ClaimID", 37, 0},   // ClaimID
	{"SerialNum", 37, 0},   // SerialNum
	/* stored in stnv partition (manufacturer data) */
};
uint32_t nv_base_address;
mico_mutex_t flash_mutex;

static void device_mutex_lock(void)
{
	if (flash_mutex == NULL)
		mico_rtos_init_mutex(&flash_mutex);
	mico_rtos_lock_mutex(&flash_mutex);
}

static void device_mutex_unlock(void)
{
	mico_rtos_unlock_mutex(&flash_mutex);
}

static int nv_get_table_idx(const char *s)
{
	int i;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (0 == strcmp(s, nv_table[i].name))
			return i;
	}
	return -1;
}

static void nv_data_preload(void)
{
	int i;
	size_t last_address;

	last_address = nv_base_address;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		IOT_DEBUG("add storage : name %s, addr %X, size %d", nv_table[i].name, nv_table[i].addr, nv_table[i].size);
	}
}

static void nv_storage_init(void)
{
	mico_logic_partition_t *info;	
	static bool intitialized;

	if (intitialized)
		return;

	info = MicoFlashGetInfo(MICO_PARTITION_USER);
	nv_base_address = info->partition_start_addr;
	mico_rtos_init_mutex(&flash_mutex);
	nv_data_preload();
	intitialized = true;
}

static int nv_storage_read(const char *store, uint8_t *buf, size_t *size)
{
	int idx;
	size_t cmp_size;
	uint8_t *tempbuf;
	uint32_t offset;
	size_t read_size;

	nv_storage_init();
	IOT_INFO("read %s size %d", store, *size);

	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -2;
	}

	read_size = (nv_table[idx].size > *size) ? *size : nv_table[idx].size;

	IOT_INFO("[read] address:0x%x, size:%d\n",nv_table[idx].addr, read_size);
	device_mutex_lock();
	offset = nv_table[idx].addr - nv_base_address;
	MicoFlashRead(MICO_PARTITION_USER, &offset , buf, read_size);
	device_mutex_unlock();

	cmp_size = read_size;
	tempbuf = malloc(cmp_size);
	if (!tempbuf) {
		IOT_ERROR("failed to malloc for tempbuf");
		return -1;
	}
	memset(tempbuf, 0xFF, cmp_size);
	if (memcmp(tempbuf, buf, cmp_size) == 0) {
		IOT_ERROR("flash was erased. write default data\n");
		free(tempbuf);
		return -2;
	}

	*size = read_size;
	free(tempbuf);
	return 0;
}

static int nv_storage_write(const char *store, uint8_t *buf, size_t size)
{
	int idx;
	uint32_t offset, no_offset = 0;
	OSStatus err = kNoErr;
	char *full_buf = NULL;

	nv_storage_init();
	IOT_INFO("write %s , size %d", store, size);

	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -1;
	}

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %d is smaller than size of write buffer %d\n", store, nv_table[idx].size, size);
		return -1;
	}

	//Read all data in front, to make sure it's not overwritten in one section
	offset = nv_table[idx].addr - nv_base_address;
	full_buf = malloc(offset + size);
	if (!full_buf) {
		IOT_ERROR("failed to malloc memory for all data.");
		return -1;
	}

	device_mutex_lock();
	MicoFlashRead(MICO_PARTITION_USER, &no_offset, full_buf, offset);
	memcpy(full_buf + offset, buf, size);
	no_offset = 0; //reset offset
	err = MicoFlashWrite(MICO_PARTITION_USER, &no_offset, full_buf, offset + size);
	device_mutex_unlock();
	if (err != kNoErr) {
		IOT_ERROR("failed to write storage header");
		free(full_buf);
		return -1;
	}

	free(full_buf);
	return size;
}

static int nv_storage_erase(const char *store)
{
	int idx;
	uint32_t offset;
	OSStatus err = kNoErr;

	nv_storage_init();

	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -1;
	}

	offset = nv_table[idx].addr - nv_base_address;
	device_mutex_lock();
	err = MicoFlashErase(MICO_PARTITION_USER, offset, nv_table[idx].size);
	device_mutex_unlock();
	if (err != kNoErr) {
		IOT_ERROR("failed to write storage header");
		return -1;
	}

	return 0;
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

	if (!buffer || *length <= 0 || *length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_READ_FAIL;

	ret = nv_storage_read(handle.filename, buffer, length);
	IOT_ERROR_CHECK(ret < -1, IOT_ERROR_FS_NO_FILE, "nvs no file");
	IOT_ERROR_CHECK(ret < 0, IOT_ERROR_FS_READ_FAIL, "nvs read fail ");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0 || length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, data, length + 1);
	IOT_ERROR_CHECK(ret <= 0, IOT_ERROR_FS_WRITE_FAIL, "nvs write fail ");

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
	IOT_ERROR_CHECK(ret != 0, IOT_ERROR_FS_REMOVE_FAIL, "nvs erase fail ");
	return IOT_ERROR_NONE;
}
