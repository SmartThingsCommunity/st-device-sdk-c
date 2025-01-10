/* ***************************************************************************
 *
 * Copyright (c) 2019-2020 Samsung Electronics All Rights Reserved.
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
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "iot_bsp_fs.h"
#include "iot_debug.h"


iot_error_t iot_bsp_fs_init()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_deinit()
{
	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_open(const char* filename, iot_bsp_fs_open_mode_t mode, iot_bsp_fs_handle_t* handle)
{
	int fd;
	int open_mode;

	if (mode == FS_READONLY) {
		if (access(filename, F_OK) < 0) {
			IOT_DEBUG("file doesn't exist");
			return IOT_ERROR_FS_NO_FILE;
		}
		open_mode = O_RDONLY;
	} else {
		open_mode = O_RDWR | O_CREAT;
	}

	fd = open(filename, open_mode, 0644);
	if (fd > 0) {
		handle->fd = fd;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("file open failed [%s]", strerror(errno));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
}

iot_error_t iot_bsp_fs_open_from_stnv(const char* filename, iot_bsp_fs_handle_t* handle)
{
	int fd;

	if (access(filename, F_OK) < 0) {
		IOT_DEBUG("file doesn't exist");
		return IOT_ERROR_FS_NO_FILE;
	}
	fd = open(filename, O_RDONLY);
	if (fd > 0) {
		handle->fd = fd;
		snprintf(handle->filename, sizeof(handle->filename), "%s", filename);
		return IOT_ERROR_NONE;
	} else {
		IOT_DEBUG("file open failed [%s]", strerror(errno));
		return IOT_ERROR_FS_OPEN_FAIL;
	}
}

iot_error_t iot_bsp_fs_read(iot_bsp_fs_handle_t handle, char* buffer, size_t *length)
{
    char* data;
    ssize_t size;

	if (access(handle.filename, F_OK) == -1) {
		IOT_DEBUG("file does not exist");
		return IOT_ERROR_FS_NO_FILE;
	}

	data = malloc(*length + 1);
	if (!data) {
	    IOT_DEBUG("malloc failed");
	    return IOT_ERROR_FS_OPEN_FAIL;
	}
	size = read(handle.fd, data, *length);
	if (size < 0) {
		free(data);
		IOT_DEBUG("read fail [%s]", strerror(errno));
		return IOT_ERROR_FS_READ_FAIL;
	}

	memcpy(buffer, data, size);
	if (size < *length) {
		buffer[size] = '\0';
	}

	*length = size;

	free(data);

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_write(iot_bsp_fs_handle_t handle, const char* data, size_t length)
{
	ssize_t size = write(handle.fd, data, length);
	IOT_DEBUG_CHECK(size != length, IOT_ERROR_FS_WRITE_FAIL, "write fail [%s]", strerror(errno));

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_close(iot_bsp_fs_handle_t handle)
{
	int ret = close(handle.fd);
	IOT_DEBUG_CHECK(ret != 0, IOT_ERROR_FS_CLOSE_FAIL, "close fail [%s]", strerror(errno));

	return IOT_ERROR_NONE;
}

iot_error_t iot_bsp_fs_remove(const char* filename)
{
	int ret = remove(filename);

	IOT_DEBUG_CHECK(((ret != 0) && (errno == ENOENT)), IOT_ERROR_FS_NO_FILE, "remove fail [%s]", strerror(errno));
	IOT_DEBUG_CHECK(ret != 0, IOT_ERROR_FS_REMOVE_FAIL, "remove fail [%s]", strerror(errno));

	return IOT_ERROR_NONE;
}
