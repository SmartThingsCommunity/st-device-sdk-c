/******************************************************************
 *
 * Copyright 2019 Samsung Electronics All Rights Reserved.
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


typedef struct nv_storage_header
{
	size_t magic;
	size_t item_cnt;
	size_t item_pos;
} nv_storage_header_s;

typedef struct nv_item_header_info
{
	size_t hash;
	size_t size;
} nv_item_header_info_s;

typedef struct nv_item_info
{
	struct nv_item_info *next;
	nv_item_header_info_s header;
	size_t addr;
} nv_item_info_s;

typedef struct nv_item_table
{
	size_t hash;
	size_t size;
	size_t addr;
} nv_item_table_s;


//#define FLASH_USR_STORAGE_BASE        0x001EF000
#define FLASH_USR_STORAGE_BASE        0x00110000
#define FLASH_USR_STORAGE_LEN         0x00005400
#define FLASH_USR_STORAGE_MAGIC       0x12345678
#define FLASH_USR_ACCESS_START        FLASH_USR_STORAGE_BASE + sizeof(nv_storage_header_s)
#define FLASH_BASE_SECTOR             0

/* reference rtl8710.h */
#define FLASH_GUARD_SIZE              256
#define FLASH_SECTOR_SIZE             4096
#define FLASH_SECTOR_SHIFT	          12
#define FLASH_MIN_SIZE                1024

#define ALIGNUP(x, y)                 ((((x) + ((y) - 1)) / (y)) * (y))

#define MAX_APP_DATA_SIZE (2048)
#define MAX_NV_ITEM_CNT				 19

#define OP_OK		1
#define OP_FAIL	-1

#define STDK_NV_SECTOR_SIZE            (0x1000)


nv_item_table_s nv_table[MAX_NV_ITEM_CNT] = {
	/* for wifi prov data */
	{0x24a05746, 65, NULL},  // WifiProvStatus
	{0x25726d8, 65, NULL},   // IotAPSSID
	{0x25723e0, 65, NULL},   // IotAPPASS
	{0xbb39a0e, 65, NULL},   // IotAPBSSID
	{0xb6bb1795, 65, NULL},   // IotAPAuthType

	/* for cloud prov data */
	{0xd317a076, 1025, NULL},   // CloudProvStatus
	{0x2892596, 1025, NULL},  // ServerURL
	{0xcadbd84, 37, NULL},   // ServerPort
	{0xc02865a, 37, NULL},  // LocationID
	{0x53a82, 37, NULL},  // RoomID
	{0xf4e0, 37, NULL},  // Lable

	{0x70012d, 129, NULL},  // DeviceID

	/* stored in stnv partition (manufacturer data) */
	{0xc96f1bc, 2049, NULL},   // PrivateKey
	{0x2860e24, 2049, NULL},   // PublicKey
	{0x4bf15, 37, NULL},   // PKType
	{0x82cac2, 2049, NULL},  // RootCert
	{0x1a7aa8, 2049, NULL},   // SubCert
	{0xaf0205e, 2049, NULL},   // DeviceCert
	{0x164c23, 37, NULL},   // ClaimID
	{0x2887a54, 37, NULL},   // SerialNum
	/* stored in stnv partition (manufacturer data) */
};

/*
 * user storage format
-------------------------------------------------------------------------------
magic(4) | item count(4) | current pos(4) | item hash(4) | item size(4) | item
-------------------------------------------------------------------------------
...| item hash(4) | item size(4) | item  ... |
-------------------------------------------------------------------------------
 */

size_t next_item_pos;
size_t iten_cnt;

static xSemaphoreHandle nv_mutex;

static size_t simple_str_hash(const unsigned char *s, size_t len)
{
	size_t key = 0;

	while (len--)
		key = 5 * key + *s++;

	return key;
}

static int nv_get_table_idx(size_t hash)
{
	int i;

	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (hash == nv_table[i].hash)
		return i;
	}
	return -1;
}

static void nv_data_preload(void)
{
	flash_t flash;
	size_t address;
	unsigned int *buf;
	int i, pos, idx;
	nv_storage_header_s header;
	size_t last_address;

	device_mutex_lock(RT_DEV_LOCK_FLASH);
	flash_stream_read(&flash, FLASH_USR_STORAGE_BASE, sizeof(nv_storage_header_s), (uint8_t *)&header);
	if (header.magic != FLASH_USR_STORAGE_MAGIC) {
		IOT_INFO("%X has not been used for user storage; using new style", FLASH_USR_STORAGE_BASE);
		goto unlock;
	}

	IOT_INFO("item count %d is already used, current item pos %d", header.item_cnt, header.item_pos);

	if (header.item_cnt == 0) {
		IOT_INFO("there is no any item in user storage");
		goto unlock;
	}

	iten_cnt = header.item_cnt;
	if (header.item_pos == 0) {
		IOT_INFO("there is no item size in user storage");
		goto unlock;
	}

	buf = malloc(header.item_pos);
	if (!buf) {
		IOT_ERROR("failed to malloc for buf");
		goto unlock;
	}

	next_item_pos = header.item_pos;
	address = FLASH_USR_ACCESS_START;
	pos = header.item_pos - sizeof(nv_storage_header_s);
	flash_stream_read(&flash, address, pos, (uint8_t *)buf);

	pos = 0;
	for (i = 0; i < iten_cnt; i++) {
		nv_item_info_s *info = malloc(sizeof(nv_item_info_s));
		size_t align_size;

		info->header.hash = buf[pos++];
		info->header.size = buf[pos++];
		info->addr = address;
		if (info->header.size > MAX_APP_DATA_SIZE)
			align_size = ALIGNUP(info->header.size, 4);
		else
			align_size = ALIGNUP(info->header.size, MAX_APP_DATA_SIZE);
		address += align_size + sizeof(nv_item_header_info_s);
		pos += align_size/sizeof(size_t);

		idx = nv_get_table_idx(info->header.hash);
		if (idx < 0) {
			free(info);
			break;
		}

		nv_table[idx].addr = info->addr + sizeof(nv_item_header_info_s);
		nv_table[idx].size = align_size;
		last_address = address;
		free(info);
		IOT_DEBUG("add storage : hash %X, addr %X, size %d", nv_table[idx].hash, nv_table[idx].addr, nv_table[idx].size);
	}

	/* fill out other address space */
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		if (nv_table[i].addr == NULL) {
			nv_table[i].addr = last_address;
			last_address += nv_table[i].size;
			IOT_DEBUG("add storage : hash %X, addr %X, size %d", nv_table[i].hash, nv_table[i].addr, nv_table[i].size);
		}
	}
	free(buf);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
	return;

	unlock:
	last_address = FLASH_USR_STORAGE_BASE;
	for (i = 0; i < MAX_NV_ITEM_CNT; i++) {
		nv_table[i].addr = last_address;
		last_address += nv_table[i].size;
		IOT_DEBUG("add storage : hash %X, addr %X, size %d", nv_table[i].hash, nv_table[i].addr, nv_table[i].size);
	}
	device_mutex_unlock(RT_DEV_LOCK_FLASH);
}

static void nv_storage_init(void)
{
	static bool intitialized;

	if (intitialized)
		return;

	nv_mutex = xSemaphoreCreateMutex();
	nv_data_preload();
	intitialized = true;
}

static long nv_storage_read(const char *store, uint8_t *buf, size_t size)
{
	nv_item_info_s *info;
	flash_t flash;
	int ret, idx;
	size_t cmp_size, hash;
	uint8_t *tempbuf;

	nv_storage_init();
	IOT_INFO("read %s size %d", store, size);

	xSemaphoreTake(nv_mutex, portMAX_DELAY);
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		xSemaphoreGive(nv_mutex);
		return -1;
	}
	xSemaphoreGive(nv_mutex);

	IOT_INFO("[read] adddress:0x%x, size:%d\n",nv_table[idx].addr, nv_table[idx].size);
	device_mutex_lock(RT_DEV_LOCK_FLASH);
	ret = flash_stream_read(&flash, nv_table[idx].addr, nv_table[idx].size, buf);
	device_mutex_unlock(RT_DEV_LOCK_FLASH);

	cmp_size = nv_table[idx].size > FLASH_MIN_SIZE ? FLASH_MIN_SIZE : nv_table[idx].size;
	tempbuf = malloc(cmp_size);
	if (!tempbuf) {
		IOT_ERROR("failed to malloc for tempbuf");
		return -1;
	}
	memset(tempbuf, 0xFF, cmp_size);
	if (memcmp(tempbuf, buf, cmp_size) == 0) {
		IOT_ERROR("flash was erased. write default data\n");
		size = IOT_ERROR_FS_NO_FILE;
	}
	free(tempbuf);
	return size;
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

	first_sector = (addr - FLASH_USR_STORAGE_BASE) >> FLASH_SECTOR_SHIFT;
	last_sector = ((addr + size - FLASH_USR_STORAGE_BASE) >> FLASH_SECTOR_SHIFT);

	backup = malloc(FLASH_SECTOR_SIZE);
	if (!backup) {
		IOT_ERROR("failed to malloc for backup");
		return -1;
	}

	specail_op_before_flash_write();
	device_mutex_lock(RT_DEV_LOCK_FLASH);
	do {
		size_t start_addr;
		size_t pos;

		start_addr = FLASH_USR_STORAGE_BASE + (first_sector << FLASH_SECTOR_SHIFT);
		flash_stream_read(&flash, start_addr, FLASH_SECTOR_SIZE, backup);
		pos = addr - start_addr;
		written = (size > (FLASH_SECTOR_SIZE - pos)) ? (FLASH_SECTOR_SIZE - pos) : size;
		if (memcmp(backup+pos, buf, written) != 0) {
			memcpy(backup+pos, buf, written);
			flash_erase_sector(&flash, start_addr);
			ret = flash_stream_write(&flash, start_addr, FLASH_SECTOR_SIZE, backup);
			if (ret <= 0) {
				free(backup);
				IOT_ERROR("failed to write storage addr %X", start_addr);
				device_mutex_unlock(RT_DEV_LOCK_FLASH);
				return ret;
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
	nv_item_info_s *info;
	flash_t flash;
	int ret, idx;
	size_t align_size, hash;

	nv_storage_init();
	IOT_INFO("write %s size %d", store, size);

	xSemaphoreTake(nv_mutex, portMAX_DELAY);
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		xSemaphoreGive(nv_mutex);
		return -1;
	}
	xSemaphoreGive(nv_mutex);

	if (size > nv_table[idx].size) {
		IOT_ERROR("%s stored size %d is smaller than size of write buffer %d\n", store, nv_table[idx].size, size);
		return -1;
	}

	ret = _flash_write(nv_table[idx].addr, size, buf);
	if (ret <= 0) {
		IOT_ERROR("failed to write storage header");
		return ret;
	}
	return size;
}

static int nv_storage_erase(const char *store)
{
	int ret, idx;
	size_t align_size, hash;
	int last_sector, first_sector;
	flash_t flash;
	uint8_t *buf;

	nv_storage_init();

	xSemaphoreTake(nv_mutex, portMAX_DELAY);
	hash = simple_str_hash(store, strlen(store));
	idx = nv_get_table_idx(hash);
	if (idx < 0) {
		IOT_ERROR("do not allow new item %s\n", store);
		xSemaphoreGive(nv_mutex);
		return -1;
	}
	xSemaphoreGive(nv_mutex);

	buf = malloc(nv_table[idx].size);
	if (!buf){
		IOT_INFO("failed to malloc for buf");
		return -1;
	}
	memset(buf, 0xFF, nv_table[idx].size);
	ret = _flash_write(nv_table[idx].addr, nv_table[idx].size, buf);
	if (ret <= 0) {
		IOT_ERROR("failed to write storage header");
		return ret;
	}
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

	if (!buffer || *length <= 0 || *length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_READ_FAIL;
	ret = nv_storage_read(handle.filename, buffer, *length);
	IOT_ERROR_CHECK(ret == OP_FAIL, IOT_ERROR_FS_READ_FAIL, "nvs read fail ");
	IOT_ERROR_CHECK(ret == IOT_ERROR_FS_NO_FILE, IOT_ERROR_FS_NO_FILE, "nvs no file");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, size_t length)
{
	int ret;

	if (!data || length <= 0 || length > STDK_NV_SECTOR_SIZE)
		return IOT_ERROR_FS_WRITE_FAIL;

	ret = nv_storage_write(handle.filename, data, length+1);
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
