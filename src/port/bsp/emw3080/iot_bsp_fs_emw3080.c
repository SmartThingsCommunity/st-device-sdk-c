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
	size_t addr;  //offset from the MICO_PARTITION_USER area
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
	int sector_count = 1;
	size_t last_address = 0;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		if (last_address >= sector_count * STDK_NV_SECTOR_SIZE) {
			//Put the file to the new sector.
			nv_table[i].addr = (sector_count++) * STDK_NV_SECTOR_SIZE;
			last_address = nv_table[i].addr + nv_table[i].size;
		}
		IOT_DEBUG("add storage : name %s, addr %zu size %zu", nv_table[i].name, nv_table[i].addr, nv_table[i].size);
	}
}

static void nv_storage_init(void)
{
	mico_logic_partition_t *info;	
	static bool intitialized;

	if (intitialized)
		return;

	info = MicoFlashGetInfo(MICO_PARTITION_USER);
	//Get the physical address here for later usage.
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

	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -2;
	}

	read_size = (nv_table[idx].size > *size) ? *size : nv_table[idx].size;

	device_mutex_lock();
	offset = nv_table[idx].addr;
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

static int MicoFlashEraseWrite(mico_partition_t partition, volatile uint32_t *off_set, uint8_t* data_addr, uint32_t size)
{
	uint32_t f_sector;
	uint32_t f_addr;
	uint8_t *f_sector_buf = NULL;
	uint32_t pos = 0;
	uint16_t s_in_sector;

	//f_addr is the sector offset
	f_sector = (*off_set) >> 12;
	f_addr = f_sector << 12;
	s_in_sector = *off_set - f_addr;

	f_sector_buf = malloc(STDK_NV_SECTOR_SIZE);
	if (!f_sector_buf) {
		IOT_ERROR("Malloc failed");
		return -1;
	}

	MicoFlashRead(partition, &f_addr, f_sector_buf, STDK_NV_SECTOR_SIZE);

	for (pos = 0; pos < size; pos++) {
		if (f_sector_buf[s_in_sector + pos] != 0xFF)
			break;
	}

	if (pos != size) {
		f_addr -= STDK_NV_SECTOR_SIZE;
		MicoFlashErase(partition, f_addr, size);

		for (pos = 0; pos < size; pos++) {
			f_sector_buf[s_in_sector + pos] = data_addr[pos];
		}
		MicoFlashWrite(partition, &f_addr, f_sector_buf, STDK_NV_SECTOR_SIZE);
	} else {
		MicoFlashWrite(partition, off_set, data_addr, size);
	}

	free(f_sector_buf);

	return kNoErr;
}

static int nv_storage_write(const char *store, uint8_t *buf, size_t size)
{
	int idx;
	uint32_t offset, no_offset = 0;
	OSStatus err = kNoErr;
	char *full_buf = NULL;

	nv_storage_init();

	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -1;
	}

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %zu is smaller than size of write buffer %zu\n", store, nv_table[idx].size, size);
		return -1;
	}

	offset = nv_table[idx].addr;

	device_mutex_lock();
	err = MicoFlashEraseWrite(MICO_PARTITION_USER, &offset, buf, size);
	device_mutex_unlock();
	if (err != kNoErr) {
		IOT_ERROR("failed to write storage header");
		return -1;
	}

	return size;
}

static int nv_storage_erase(const char *store)
{
	int idx;
	char *buff;

	nv_storage_init();
	idx = nv_get_table_idx(store);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		return -1;
	}

	buff = (char *)malloc(nv_table[idx].size);
	if (!buff) {
		IOT_ERROR("failed to malloc memory for all data.");
		return -1;
	}

	memset(buff, 0xFF, nv_table[idx].size);
	nv_storage_write(store, (uint8_t *)buff, nv_table[idx].size);

	free(buff);

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

	ret = nv_storage_read(handle.filename, (uint8_t *)buffer, length);
	IOT_ERROR_CHECK(ret < -1, IOT_ERROR_FS_NO_FILE, "nvs no file");
	IOT_ERROR_CHECK(ret < 0, IOT_ERROR_FS_READ_FAIL, "nvs read fail ");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0 || length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, (uint8_t *)data, length + 1);
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
