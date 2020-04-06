/* ***************************************************************************
 *
 * Copyright 2019-2020 Samsung Electronics All Rights Reserved.
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

#include <stdio.h>
#include <string.h>
#include "iot_bsp_fs.h"
#include "iot_bsp_debug.h"


/*
 * Using LittleFileSystem as underlying storage
 */

#include "mbed.h"
#include <stdio.h>
#include <errno.h>

#include "BlockDevice.h"
#include "LittleFileSystem.h" /*TODO: check other filesystems */

// This will take the system's default block device
static BlockDevice *bd = BlockDevice::get_default_instance(); /* TODO: you can define your own block device */

static LittleFileSystem fs("fs");

/* TODO: identify the requirement for erase */
/* To reformat the file system */
#if 0
static void erase_fs()
{
	IOT_INFO("Initializing the block device... ");
	fflush(stdout);
	int err = bd->init();
	IOT_INFO("%s", (err ? "Fail :(" : "OK"));
	if (err) {
		IOT_ERROR("error: %s (%d)", strerror(-err), err);
	}

	IOT_INFO("Erasing the block device of size %d", bd->size());
	fflush(stdout);
	err = bd->erase(0, bd->size());
	IOT_INFO("%s", (err ? "Fail :(" : "OK"));
	if (err) {
		IOT_ERROR("error: %s (%d)", strerror(-err), err);
	}

	IOT_INFO("Deinitializing the block device... ");
	fflush(stdout);
	err = bd->deinit();
	IOT_INFO("%s", (err ? "Fail :(" : "OK"));
	if (err) {
		IOT_ERROR("error: %s (%d)", strerror(-err), err);
	}
}
#endif

iot_error_t iot_bsp_fs_init()
{
	//Reset Block Device
	//	erase_fs();

	// Try to mount the filesystem
	IOT_INFO("Mounting the filesystem... ");
	fflush(stdout);
	int err = fs.mount(bd);
	IOT_INFO("%s", (err ? "Fail :(" : "OK"));
	if (err) {
		// Reformat if we can't mount the filesystem
		// this should only happen on the first boot
		IOT_INFO("No filesystem found, formatting... ");
		fflush(stdout);
		err = fs.reformat(bd);
		IOT_INFO("%s", (err ? "Fail :(" : "OK"));
		if (err) {
			IOT_ERROR("error: %s (%d)\n", strerror(-err), err);
			return IOT_ERROR_INIT_FAIL;
		}
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	IOT_INFO("Unmounting... ");
	fflush(stdout);
	int err = fs.unmount();
	IOT_INFO("%s", (err < 0 ? "Fail :(" : "OK"));
	if (err < 0) {
		IOT_ERROR("error: %s (%d)", strerror(-err), err);
		return IOT_ERROR_INIT_FAIL;
	}
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char *filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t *handle)
{
	FILE *f = NULL;

	IOT_DEBUG("Open File: %s", filename);
	if (mode == FS_READONLY) {
		fflush(stdout);
		f = fopen(filename, "r+");
		IOT_DEBUG("%s", (!f ? "Fail :(" : "OK"));
		if (!f) {
			IOT_ERROR("error: %s (%d) (%s)", strerror(errno), -errno, filename);
			return IOT_ERROR_FS_OPEN_FAIL;
		}
	} else {
		fflush(stdout);
		f = fopen(filename, "w+");
		IOT_DEBUG("%s", (!f ? "Fail :(" : "OK"));
		if (!f) {
			IOT_ERROR("error: %s (%d) (%s)", strerror(errno), -errno, filename);
			return IOT_ERROR_FS_OPEN_FAIL;
		}
	}

	handle->fd = (int)f;
	snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open_from_stnv(const char *filename, iot_bsp_fs_handle_t *handle)
{
	return iot_bsp_fs_open(filename, FS_READONLY, handle);
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char *buffer, unsigned int length)
{
	int ret = -1;

	FILE *f = (FILE *) handle.fd;
	if (!f) {
		IOT_ERROR("File Not Open %s", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	}

	fflush(stdout);
	IOT_DEBUG("Reading From File: %s", handle.filename);
	for (unsigned int i = 0; !feof(f) && i < length; i++) {
		buffer[i] = fgetc(f);
		ret = i;
	}
	buffer[ret] = 0x00;
	if (ret <= 0) {
		IOT_ERROR("Read Failed for %s [0x%x]", handle.filename, ret);
		return IOT_ERROR_FS_READ_FAIL;
	} else {
		IOT_DEBUG("Bytes Read [%d]", ret);
		//for (int i=0;i<ret; i++) {printf("%02x ", buffer[i]);} printf("\n");
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char *data, unsigned int length)
{
	int ret;
	FILE *f = (FILE*) handle.fd;
	if (!f) {
		IOT_ERROR("ERROR: File Not Open %s", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	}

	IOT_DEBUG("Seek to END");
	fflush(stdout);
	ret = fseek(f, 0, SEEK_END);
	if (ret < 0) {
		IOT_ERROR("Seek Failed for %s | %s [0x%x]", handle.filename,
				strerror(errno), -errno);
		return IOT_ERROR_FS_WRITE_FAIL;
	}
	IOT_DEBUG("%s", (ret < 0 ? "Fail :(" : "OK"));

	IOT_DEBUG("Writing To File: %s", handle.filename);
	fflush(stdout);
	for (unsigned int i = 0; i < length; i++) {
		fputc(data[i], f);
		//printf("%02x ", data[i]);
		ret = i + 1;
	}
//	printf("\n");

	if (ret <= 0) {
		IOT_ERROR("Write Failed for %s [0x%x]", handle.filename, ret);
		return IOT_ERROR_FS_WRITE_FAIL;
	} else {
		IOT_DEBUG("Bytes Written [%d]", ret);
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	int ret;
	FILE *f = (FILE *)handle.fd;
	if (!f) {
		IOT_ERROR("ERROR: File Not Open %s", handle.filename);
		return IOT_ERROR_FS_NO_FILE;
	}

	fflush(stdout);
	ret = fclose(f);
	if (ret < 0) {
		IOT_ERROR("Close Failed for %s [0x%x]", handle.filename, ret);
		return IOT_ERROR_FS_CLOSE_FAIL;
	}

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char *filename)
{
	FILE *f = fopen(filename, "r");
	if (!f) {
		IOT_ERROR("error: %s (%d) (%s)", strerror(errno), -errno, filename);
		return IOT_ERROR_FS_NO_FILE;
	}
	fflush(stdout);
	int close = fclose(f);
	if (close < 0) {
		IOT_ERROR("Close Failed for %s [0x%x]", filename, close);
	}

	int ret = remove(filename);
	if (ret < 0) {
		IOT_ERROR("Delete Failed for %s [0x%x]", filename, ret);
		return IOT_ERROR_FS_REMOVE_FAIL;
	}
	IOT_WARN("Delete Successful for file %s", filename);
	return IOT_ERROR_NONE;
}
