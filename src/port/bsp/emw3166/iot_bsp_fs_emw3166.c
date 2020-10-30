/* ***************************************************************************
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

#include "mico.h"
#include "mico_filesystem.h"
#include "FreeRTOS.h"
#include "semphr.h"
#include "iot_bsp_fs.h"
#include "iot_debug.h"

//mico system need to use this mount name as fs partition
#define EMW_IOT_MOUNT_NAME      "0:"
#define EMW_IOT_FSSIZE          0x10000  //64K
#define EMW_IOT_BLOCK_SIZE      8  //FS operating with each 8bytes
#define EMW_IOT_FD_NUM          128

static bool initialized = false;
static mico_filesystem_t iot_fs_handle;

mico_file_t* iot_fd_table[EMW_IOT_FD_NUM];
static xSemaphoreHandle fd_mutex = NULL;

static int _get_available_fd(void)
{
	int i = 0;

	xSemaphoreTake((SemaphoreHandle_t)fd_mutex, portMAX_DELAY);

	for (; i < EMW_IOT_FD_NUM; i++) {
		if (iot_fd_table[i] == NULL)
		{
			xSemaphoreGive(fd_mutex);
			return i;
		}
	}

	xSemaphoreGive(fd_mutex);
	return -1;
}

static void _set_mico_fh(int fd, mico_file_t *mico_fh)
{
	xSemaphoreTake((SemaphoreHandle_t)fd_mutex, portMAX_DELAY);
	iot_fd_table[fd] = mico_fh;
	xSemaphoreGive(fd_mutex);
}

static mico_file_t* _get_mico_fh(int fd)
{
	if (fd < 0 || fd >= EMW_IOT_FD_NUM)
		return NULL;

	return iot_fd_table[fd];
}


const mico_block_device_init_data_t _block_device_init_data =
{
	.base_address_offset = 0,
	.maximum_size = 0,
	.volatile_and_requires_format_when_mounting = 0,
};

mico_block_device_t iot_block_device =
{
	.init_data = &_block_device_init_data,
	.driver = &tester_block_device_driver,
	.device_size = EMW_IOT_FSSIZE,

	/* for format */
	.erase_block_size = EMW_IOT_BLOCK_SIZE,
	.write_block_size = EMW_IOT_BLOCK_SIZE,
	.read_block_size = EMW_IOT_BLOCK_SIZE,
};

static iot_error_t _iot_bsp_mico_fs_init(void)
{
	OSStatus err = kNoErr;

	/* Initialize mico file system. */
	mico_filesystem_init( );

	/* Mount FATFS file system. */
	err = mico_filesystem_mount(&iot_block_device, MICO_FILESYSTEM_HANDLE_FATFS, &iot_fs_handle, EMW_IOT_MOUNT_NAME);
	IOT_ERROR_CHECK(err != kNoErr, IOT_ERROR_INIT_FAIL, "mico filesystem mount fail");

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_init(void)
{
	iot_error_t ret = IOT_ERROR_NONE;
	mico_filesystem_info fatfs_info = { 0 };

	if (initialized)
		return IOT_ERROR_NONE;

	memset(iot_fd_table, 0, sizeof(iot_fd_table));
	fd_mutex = xSemaphoreCreateMutex();
	if (fd_mutex == NULL) {
		IOT_ERROR("xSemaphoreCreateMutex failed");
		return IOT_ERROR_INIT_FAIL;
	}

	ret = _iot_bsp_mico_fs_init();
	if (ret != IOT_ERROR_NONE) {
		vSemaphoreDelete(fd_mutex);
		IOT_ERROR("mico fs init failed");
		return IOT_ERROR_INIT_FAIL;
	}

	mico_filesystem_get_info(&iot_fs_handle, &fatfs_info, (char *)EMW_IOT_MOUNT_NAME);
	if (fatfs_info.free_space <= 0) {
		IOT_INFO("Format filesystem");
		mico_filesystem_format(&iot_block_device, MICO_FILESYSTEM_HANDLE_FATFS);
	}

	initialized = true;
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit(void)
{
	mico_filesystem_unmount(&iot_fs_handle);

	if (fd_mutex)
		vSemaphoreDelete(fd_mutex);

	initialized = false;

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	int bsp_fd;
	OSStatus err = kNoErr;
	mico_filesystem_open_mode_t mico_mode;
	mico_file_t *fh = NULL;
	iot_error_t ret = IOT_ERROR_NONE;

	bsp_fd = _get_available_fd();
	if (bsp_fd == -1) {
		IOT_ERROR("no more fd");
		return IOT_ERROR_FS_OPEN_FAIL;
	}

	mico_mode = (mode == FS_READONLY)? MICO_FILESYSTEM_OPEN_FOR_READ : MICO_FILESYSTEM_OPEN_WRITE_CREATE;
	fh = (mico_file_t*)malloc(sizeof(mico_file_t));
	IOT_ERROR_CHECK(fh == NULL, IOT_ERROR_MEM_ALLOC, "malloc file handle failed");

	err = mico_filesystem_file_open(&iot_fs_handle, fh, filename, mico_mode);
	if (err != kNoErr) {
		if (mico_mode == MICO_FILESYSTEM_OPEN_WRITE_CREATE) {
			IOT_ERROR("mico fs create fail or open fail in writing mode");
			ret = IOT_ERROR_FS_OPEN_FAIL;
		} else if (mico_mode == MICO_FILESYSTEM_OPEN_FOR_READ) {
			IOT_INFO("mico fs open fail in read mode, no such file.");
			ret = IOT_ERROR_FS_NO_FILE;
		}
		free(fh);
	}

	_set_mico_fh(bsp_fd, fh);

	handle->fd = bsp_fd;
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);

	return ret;
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
	iot_error_t ret = IOT_ERROR_NONE;
	OSStatus err = kNoErr;
	mico_file_t *fh;
	unsigned int bytesread = 0;
	uint64_t mico_len = 0;
	char* data = NULL;

	IOT_ERROR_CHECK(handle.fd >= EMW_IOT_FD_NUM, IOT_ERROR_INVALID_ARGS, "Invalid fd %d", handle.fd);
	fh = _get_mico_fh(handle.fd);
	IOT_ERROR_CHECK(fh == NULL, IOT_ERROR_FS_READ_FAIL, "no mico file handle for fd");

	data = (char*)malloc(fh->data.fatfs.fsize);
	IOT_ERROR_CHECK(data == NULL, IOT_ERROR_MEM_ALLOC, "malloc data buffer failed");
	memset(data, 0, fh->data.fatfs.fsize);

	err = mico_filesystem_file_read(fh, data, fh->data.fatfs.fsize, &mico_len);
	bytesread = mico_len;
	if (err == kNoErr) {
		bytesread = ((strlen(data) + 1) < bytesread)? (strlen(data) + 1) : bytesread;
		memcpy(buffer, data, bytesread);
		IOT_INFO("bsp fs read %u bytes, data length %d", bytesread, strlen(data));
		*length = bytesread;
	} else {
		IOT_ERROR("mico fs return %d, read bytes %d", err, bytesread);
		ret = IOT_ERROR_FS_READ_FAIL;
	}

	free(data);

	return ret;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, size_t length)
{
	mico_file_t *fh;
	OSStatus err = kNoErr;
	uint64_t byteswritten = 0;

	IOT_ERROR_CHECK(handle.fd >= EMW_IOT_FD_NUM, IOT_ERROR_INVALID_ARGS, "Invalid fd %d", handle.fd);
	fh = _get_mico_fh(handle.fd);
	IOT_ERROR_CHECK(fh == NULL, IOT_ERROR_FS_WRITE_FAIL, "no mico file handle for fd");

	err = mico_filesystem_file_write(fh, data, length, &byteswritten);
	IOT_INFO("return %d, length %d, fs write %llu bytes", err, length, byteswritten);

	return (err == kNoErr)? IOT_ERROR_NONE : IOT_ERROR_FS_WRITE_FAIL;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	mico_file_t *fh;
	OSStatus err = kNoErr;

	IOT_ERROR_CHECK(handle.fd >= EMW_IOT_FD_NUM, IOT_ERROR_INVALID_ARGS, "Invalid fd %d", handle.fd);
	fh = _get_mico_fh(handle.fd);
	if (fh) {
		err = mico_filesystem_file_close(fh);
		free(fh);
	}
	_set_mico_fh(handle.fd, NULL);

	return (err == kNoErr)? IOT_ERROR_NONE : IOT_ERROR_FS_CLOSE_FAIL;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	OSStatus err = kNoErr;

	/*return MICO_FILESYSTEM_ERROR for all abnormal cases, including no file case,
	  so we just give a message here, but not return error*/
	err = mico_filesystem_file_delete(&iot_fs_handle, filename);
	if (err != kNoErr) {
		IOT_ERROR("%s is not removed normally, maybe something wrong or no such file.", filename);
	}

	return IOT_ERROR_NONE;
}
